//! Canonical target parsing and normalization for network perimeter scanning.
//!
//! Complies with RFC 791 (IPv4), RFC 4291 (IPv6), and RFC 1123 (Hostnames).
//! Guarantees strict canonicalization, strips schemes/paths, and normalizes
//! IPv4-mapped IPv6 addresses to standard IPv4 representations.

use crate::error::NetworkError;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

/// Validated classification of the network target type.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TargetType {
    /// Canonical IPv4 address (RFC 791).
    Ipv4(Ipv4Addr),
    /// Canonical IPv6 address (RFC 4291).
    Ipv6(Ipv6Addr),
    /// RFC 1123 compliant fully-qualified domain name or hostname.
    Hostname(String),
}

/// A parsed, normalized, and validated perimeter assessment target.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CanonicalTarget {
    /// Raw unparsed operator input string.
    pub raw_input: String,
    /// Canonical host string (lowercase, brackets/schemes stripped, normalized).
    pub normalized_host: String,
    /// Classified target representation.
    pub target_type: TargetType,
    /// Optional explicitly specified port.
    pub port: Option<u16>,
}

impl CanonicalTarget {
    /// Parses and normalizes an input target string.
    ///
    /// Accepts:
    /// - IPv4: `192.0.2.1` or `192.0.2.1:8080`
    /// - IPv6: `::1`, `[::1]`, `[2001:db8::1]:443`, `2001:db8::1`
    /// - IPv4-mapped IPv6: `::ffff:192.0.2.1` or `[::ffff:192.0.2.1]:80` -> mapped to IPv4 `192.0.2.1`
    /// - Hostnames: `example.com`, `sub.example.com:8443`, `https://example.com/path` -> `example.com`
    pub fn parse(input: &str) -> Result<Self, NetworkError> {
        let trimmed = input.trim();
        if trimmed.is_empty() {
            return Err(NetworkError::TargetParse(
                "Target string cannot be empty".into(),
            ));
        }

        // 1. Strip scheme prefix if accidentally provided (e.g. "https://", "http://")
        let without_scheme = if let Some(idx) = trimmed.find("://") {
            &trimmed[idx + 3..]
        } else {
            trimmed
        };

        // 2. Strip trailing paths, queries, or fragments if provided (e.g. "example.com/api/v1")
        let host_port_part = without_scheme
            .split(&['/', '?', '#'][..])
            .next()
            .unwrap_or("");
        if host_port_part.is_empty() {
            return Err(NetworkError::TargetParse(
                "Missing host in target specification".into(),
            ));
        }

        // 3. Separate host and port
        let (host_str, port) = parse_host_and_port(host_port_part)?;

        // 4. Try parsing as IPv4
        if let Ok(ipv4) = host_str.parse::<Ipv4Addr>() {
            return Ok(Self {
                raw_input: input.to_string(),
                normalized_host: ipv4.to_string(),
                target_type: TargetType::Ipv4(ipv4),
                port,
            });
        }

        // 5. Try parsing as IPv6
        let unbracketed = host_str.trim_start_matches('[').trim_end_matches(']');
        if let Ok(ipv6) = unbracketed.parse::<Ipv6Addr>() {
            // Check for IPv4-mapped IPv6 (::ffff:x.x.x.x) and canonicalize to pure IPv4
            if let Some(ipv4) = ipv6.to_ipv4_mapped() {
                return Ok(Self {
                    raw_input: input.to_string(),
                    normalized_host: ipv4.to_string(),
                    target_type: TargetType::Ipv4(ipv4),
                    port,
                });
            }

            return Ok(Self {
                raw_input: input.to_string(),
                normalized_host: ipv6.to_string(),
                target_type: TargetType::Ipv6(ipv6),
                port,
            });
        }

        // 6. Validate as RFC 1123 Hostname
        let normalized_hostname = validate_and_normalize_hostname(host_str)?;

        Ok(Self {
            raw_input: input.to_string(),
            normalized_host: normalized_hostname.clone(),
            target_type: TargetType::Hostname(normalized_hostname),
            port,
        })
    }

    /// Returns the effective IP address if target is already an IP literal.
    #[must_use]
    pub fn as_ip(&self) -> Option<IpAddr> {
        match &self.target_type {
            TargetType::Ipv4(ip) => Some(IpAddr::V4(*ip)),
            TargetType::Ipv6(ip) => Some(IpAddr::V6(*ip)),
            TargetType::Hostname(_) => None,
        }
    }
}

/// Helper to parse host and optional port from a string like "host:port", "[ipv6]:port", or "host".
fn parse_host_and_port(input: &str) -> Result<(&str, Option<u16>), NetworkError> {
    if input.starts_with('[') {
        // Bracketed IPv6: e.g. "[2001:db8::1]:443" or "[2001:db8::1]"
        if let Some(closing_bracket) = input.find(']') {
            let host = &input[1..closing_bracket];
            let remainder = &input[closing_bracket + 1..];
            if remainder.is_empty() {
                Ok((host, None))
            } else if let Some(port_str) = remainder.strip_prefix(':') {
                let port = port_str.parse::<u16>().map_err(|_| {
                    NetworkError::TargetParse(format!("Invalid port number: '{port_str}'"))
                })?;
                Ok((host, Some(port)))
            } else {
                Err(NetworkError::TargetParse(format!(
                    "Malformed bracketed address: '{input}'"
                )))
            }
        } else {
            Err(NetworkError::TargetParse(
                "Unmatched '[' in IPv6 address".into(),
            ))
        }
    } else {
        // Could be "host:port" or bare IPv4 or bare IPv6 (unbracketed with multiple colons)
        let colon_count = input.chars().filter(|&c| c == ':').count();
        if colon_count == 1 {
            // Standard "host:port"
            let (host, port_str) = input.split_once(':').unwrap();
            let port = port_str.parse::<u16>().map_err(|_| {
                NetworkError::TargetParse(format!("Invalid port number: '{port_str}'"))
            })?;
            Ok((host, Some(port)))
        } else {
            // Bare hostname, bare IPv4, or unbracketed IPv6
            Ok((input, None))
        }
    }
}

/// Validates and normalizes an RFC 1123 hostname.
fn validate_and_normalize_hostname(input: &str) -> Result<String, NetworkError> {
    let lower = input.to_ascii_lowercase();
    let trimmed = lower.trim_end_matches('.');

    if trimmed.is_empty() {
        return Err(NetworkError::TargetParse("Hostname cannot be empty".into()));
    }

    if trimmed.len() > 253 {
        return Err(NetworkError::TargetParse(format!(
            "Hostname exceeds maximum 253 characters (length: {})",
            trimmed.len()
        )));
    }

    // Prohibit cloud metadata pseudo-hostnames immediately
    if trimmed == "metadata.google.internal"
        || trimmed == "metadata.tld"
        || trimmed.ends_with(".metadata.google.internal")
    {
        return Err(NetworkError::TargetParse(format!(
            "Forbidden cloud metadata hostname: '{trimmed}'"
        )));
    }

    for label in trimmed.split('.') {
        if label.is_empty() {
            return Err(NetworkError::TargetParse(
                "Hostname contains consecutive or invalid empty labels".into(),
            ));
        }

        if label.len() > 63 {
            return Err(NetworkError::TargetParse(format!(
                "Hostname label exceeds 63 characters: '{label}'"
            )));
        }

        if label.starts_with('-') || label.ends_with('-') {
            return Err(NetworkError::TargetParse(format!(
                "Hostname label cannot start or end with hyphen: '{label}'"
            )));
        }

        if !label.chars().all(|c| c.is_ascii_alphanumeric() || c == '-') {
            return Err(NetworkError::TargetParse(format!(
                "Hostname label contains invalid character: '{label}'"
            )));
        }
    }

    Ok(trimmed.to_string())
}
