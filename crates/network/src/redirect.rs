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
        let absolute_location = if location.starts_with('/') {
            let port_str = if origin.pinned_addr.port() == 80 || origin.pinned_addr.port() == 443 {
                String::new()
            } else {
                format!(":{}", origin.pinned_addr.port())
            };
            format!("http://{}{}{}", origin.sni_hostname, port_str, location)
        } else if !location.contains("://") {
            format!("http://{}/{}", origin.sni_hostname, location)
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

        // Re-resolve, re-validate all addresses, and pin new target
        let new_pinned =
            resolve_and_pin(&new_target, scope, resolver, default_port).map_err(|e| {
                NetworkError::RedirectViolation(format!(
                    "Redirect destination '{location}' violates security scope: {e}"
                ))
            })?;

        Ok(new_pinned)
    }
}
