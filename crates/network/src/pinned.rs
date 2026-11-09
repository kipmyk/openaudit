//! Pinned destination address for subsequent TCP, TLS, and HTTP operations.
//!
//! Separates the physical network destination socket address from the logical
//! host identity, guaranteeing immunity to DNS rebinding while preserving TLS
//! Server Name Indication (SNI) and HTTP Host header compliance.

use crate::scope::IpClassification;
use crate::target::CanonicalTarget;
use std::net::SocketAddr;

/// An immutable, validated, pinned network target.
///
/// Ensures that once an IP address is authorized and validated, all subsequent
/// socket connections (`TcpStream::connect`) connect strictly to `pinned_addr`,
/// preventing time-of-check to time-of-use (TOCTOU) DNS rebinding attacks.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PinnedTarget {
    /// Canonical parsed representation of the target.
    pub canonical_target: CanonicalTarget,
    /// Verified, pinned destination socket address (IP + Port).
    pub pinned_addr: SocketAddr,
    /// Logical hostname string preserved for TLS SNI and HTTP Host header.
    pub sni_hostname: String,
    /// Verified security classification of the pinned IP.
    pub classification: IpClassification,
}

impl PinnedTarget {
    /// Returns the raw socket address to connect to.
    #[must_use]
    pub fn socket_addr(&self) -> SocketAddr {
        self.pinned_addr
    }

    /// Returns the SNI hostname for TLS client handshakes.
    #[must_use]
    pub fn sni_hostname(&self) -> &str {
        &self.sni_hostname
    }

    /// Returns the HTTP Host header value (including non-standard port if applicable).
    #[must_use]
    pub fn http_host_header(&self) -> String {
        let port = self.pinned_addr.port();
        if port == 80 || port == 443 {
            self.sni_hostname.clone()
        } else {
            format!("{}:{}", self.sni_hostname, port)
        }
    }
}
