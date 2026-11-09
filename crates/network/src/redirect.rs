//! Safe redirect validation against authorized scope and SSRF boundaries.
//!
//! Enforces:
//! - Re-evaluation of all HTTP 3xx Location header destinations against `TargetScope`.
//! - Strict hop limit to prevent redirect loops.
//! - Defense against redirect-based SSRF (e.g. redirecting from public site to 169.254.169.254).

use crate::error::NetworkError;
use crate::pinned::PinnedTarget;
use crate::resolver::{resolve_and_pin, DnsResolver};
use crate::scope::TargetScope;
use crate::target::CanonicalTarget;
use std::net::SocketAddr;

/// Validates HTTP redirection chains against security scope policies.
#[derive(Debug, Clone)]
pub struct RedirectValidator {
    /// Maximum allowed redirect hops before aborting (default: 5).
    pub max_hops: usize,
}

impl Default for RedirectValidator {
    fn default() -> Self {
        Self { max_hops: 5 }
    }
}

impl RedirectValidator {
    /// Creates a new validator with custom maximum hop count.
    #[must_use]
    pub fn with_max_hops(max_hops: usize) -> Self {
        Self { max_hops }
    }

    /// Evaluates a redirect location header and returns a new `PinnedTarget` if authorized.
    ///
    /// Never trusts a redirect simply because the original target was authorized!
    pub fn validate_redirect<R: DnsResolver>(
        &self,
        current_hop: usize,
        location: &str,
        origin: &PinnedTarget,
        scope: &TargetScope,
        resolver: &R,
    ) -> Result<PinnedTarget, NetworkError> {
        if current_hop >= self.max_hops {
            return Err(NetworkError::RedirectViolation(format!(
                "Redirect hop limit exceeded ({}/{})",
                current_hop, self.max_hops
            )));
        }

        // Handle relative URLs (e.g. "/login" or "path/to/page")
        let scheme = if origin.pinned_addr.port() == 443 {
            "https"
        } else {
            "http"
        };
        let absolute_location = if location.starts_with('/') {
            let port_str = if origin.pinned_addr.port() == 80 || origin.pinned_addr.port() == 443 {
                String::new()
            } else {
                format!(":{}", origin.pinned_addr.port())
            };
            format!("{scheme}://{}{}{}", origin.sni_hostname, port_str, location)
        } else if !location.contains("://") {
            format!("{scheme}://{}/{}", origin.sni_hostname, location)
        } else {
            location.to_string()
        };

        // Parse new target
        let new_target = CanonicalTarget::parse(&absolute_location)?;

        // Default port based on scheme in location
        let default_port = if absolute_location.starts_with("https://") {
            443
        } else {
            80
        };

        // If target host matches the origin, reuse the already validated pinned IP address
        // to prevent DNS rebinding attacks during redirection and avoid redundant lookups.
        if new_target.normalized_host == origin.canonical_target.normalized_host {
            let port = new_target.port.unwrap_or(default_port);
            let pinned_addr = SocketAddr::new(origin.pinned_addr.ip(), port);
            let classification = scope.validate_destination(pinned_addr.ip()).map_err(|e| {
                NetworkError::RedirectViolation(format!(
                    "Redirect destination '{location}' violates security scope: {e}"
                ))
            })?;
            Ok(PinnedTarget {
                canonical_target: new_target,
                pinned_addr,
                sni_hostname: origin.sni_hostname.clone(),
                classification,
            })
        } else {
            // Destination host differs: resolve, validate ALL returned addresses, and pin new target
            resolve_and_pin(&new_target, scope, resolver, default_port).map_err(|e| {
                NetworkError::RedirectViolation(format!(
                    "Redirect destination '{location}' violates security scope: {e}"
                ))
            })
        }
    }
}
