//! Canonical target parsing and input hardening for perimeter scanning.
//!
//! Complies with RFC 791 (IPv4), RFC 4291 (IPv6), and RFC 1123 (Hostnames).
//! Enforces strict validation:
//! - Rejects URL userinfo (`user:pass@host` or `user@host`).
//! - Rejects unsupported schemes (only `http://`, `https://`, or bare targets allowed).
//! - Rejects port 0 or out-of-range ports (`1..=65535` enforced).
//! - Rejects malformed brackets, empty hostnames, and RFC 1123 violations.
//! - Canonicalizes IPv4-mapped IPv6 (`::ffff:x.x.x.x`) to standard IPv4.

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
    /// Optional explicitly specified port (1..=65535).
    pub port: Option<u16>,
}

impl CanonicalTarget {
    /// Parses, hardens, and normalizes an input target string.
    pub fn parse(input: &str) -> Result<Self, NetworkError> {
        let trimmed = input.trim();
        if trimmed.is_empty() {
            return Err(NetworkError::TargetParse(
                "Target string cannot be empty".into(),
            ));
        }

        // 1. Prohibit control characters or whitespace within target
        if trimmed.chars().any(char::is_whitespace) {
            return Err(NetworkError::TargetParse(
                "Target string cannot contain internal whitespace".into(),
            ));
        }

        // 2. Validate and strip scheme prefix
        let without_scheme = if let Some(idx) = trimmed.find("://") {
            let scheme = &trimmed[..idx].to_ascii_lowercase();
            if scheme != "http" && scheme != "https" {
                return Err(NetworkError::TargetParse(format!(
                    "Unsupported scheme '{scheme}': only http, https, or bare targets are permitted"
                )));
            }
            &trimmed[idx + 3..]
        } else {
            trimmed
        };

        // 3. Prohibit userinfo (e.g. "admin@host" or "user:pass@host") to prevent credential injection
        if without_scheme.contains('@') {
            return Err(NetworkError::TargetParse(
                "Target cannot contain URL userinfo or '@' authority component".into(),
            ));
        }

        // 4. Strip trailing paths, queries, or fragments if provided (e.g. "example.com/api/v1?q=1#frag")
        let host_port_part = without_scheme
            .split(&['/', '?', '#'][..])
            .next()
            .unwrap_or("");
        if host_port_part.is_empty() {
            return Err(NetworkError::TargetParse(
                "Missing host in target specification".into(),
            ));
        }

        // 5. Separate host and port
        let (host_str, port) = parse_host_and_port(host_port_part)?;

        // 6. Try parsing as IPv4
        if let Ok(ipv4) = host_str.parse::<Ipv4Addr>() {
            return Ok(Self {
                raw_input: input.to_string(),
                normalized_host: ipv4.to_string(),
                target_type: TargetType::Ipv4(ipv4),
                port,
            });
        }

        // 7. Try parsing as IPv6
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

        // 8. Validate as RFC 1123 Hostname
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
        let closing_bracket = input.find(']').ok_or_else(|| {
            NetworkError::TargetParse("Unmatched '[': bracketed IPv6 must end with ']'".into())
        })?;

        let host = &input[1..closing_bracket];
        if host.is_empty() {
            return Err(NetworkError::TargetParse(
                "Empty IPv6 address in brackets '[]'".into(),
            ));
        }

        let remainder = &input[closing_bracket + 1..];
        if remainder.is_empty() {
            Ok((host, None))
        } else if let Some(port_str) = remainder.strip_prefix(':') {
            let port = validate_port(port_str)?;
            Ok((host, Some(port)))
        } else {
            Err(NetworkError::TargetParse(format!(
                "Malformed characters after closing bracket: '{remainder}'"
            )))
        }
    } else {
        // Unbracketed target
        if input.contains(']') {
            return Err(NetworkError::TargetParse(
                "Unexpected ']' without leading '['".into(),
            ));
        }

        let colon_count = input.chars().filter(|&c| c == ':').count();
        if colon_count == 1 {
            // Standard "host:port" or "ipv4:port"
            let (host, port_str) = input.split_once(':').unwrap();
            if host.is_empty() {
                return Err(NetworkError::TargetParse(
                    "Missing host before ':' in host:port".into(),
                ));
            }
            let port = validate_port(port_str)?;
            Ok((host, Some(port)))
        } else {
            // Bare hostname, bare IPv4, or unbracketed IPv6 literal (multiple colons)
            Ok((input, None))
        }
    }
}

/// Validates that a port string is numeric and between 1 and 65535 (port 0 rejected).
fn validate_port(port_str: &str) -> Result<u16, NetworkError> {
    if port_str.is_empty() {
        return Err(NetworkError::TargetParse(
            "Port string cannot be empty".into(),
        ));
    }
    let port = port_str.parse::<u16>().map_err(|_| {
        NetworkError::TargetParse(format!(
            "Invalid port number: '{port_str}' (must be 1-65535)"
        ))
    })?;
    if port == 0 {
        return Err(NetworkError::TargetParse(
            "Port 0 is reserved and invalid for perimeter scanning".into(),
        ));
    }
    Ok(port)
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
