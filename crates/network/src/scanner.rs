//! Bounded, safe TCP connection discovery for perimeter assessments.
//!
//! Enforces:
//! - Strictly bounded port count (maximum 1024 ports).
//! - Strict connection timeouts (default 1000ms, maximum 5000ms).
//! - Rate limits and bounded concurrency.
//! - Direct connection to the pinned IP address (zero secondary DNS lookups).
//! - Non-destructive: opens connection and immediately shuts down cleanly.
//! - Categorizes results: `Open`, `Closed` (RST/refused), `Filtered` (timeout/unreachable).

use crate::error::NetworkError;
use crate::pinned::PinnedTarget;
use std::io::ErrorKind;
use std::net::{Shutdown, SocketAddr, TcpStream};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::thread;
use std::time::{Duration, Instant};

/// Observed state of a destination TCP port.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PortStatus {
    /// Port accepted TCP connection (SYN-ACK received, handshake completed).
    Open,
    /// Port actively rejected TCP connection (RST received, connection refused).
    Closed,
    /// Port dropped packets or failed to respond within timeout (filtered by firewall).
    Filtered,
}

/// Structured forensic result for a single probed TCP port.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PortScanResult {
    /// The probed TCP port number.
    pub port: u16,
    /// Observed port state.
    pub status: PortStatus,
    /// Connection round-trip latency in milliseconds.
    pub latency_ms: u64,
    /// Additional error diagnostic (if closed or filtered).
    pub diagnostic: Option<String>,
}

/// Configuration governing safe, bounded TCP discovery.
#[derive(Debug, Clone)]
pub struct TcpScanConfig {
    /// Ordered list of unique ports to probe (max 1024).
    pub ports: Vec<u16>,
    /// Per-port connection timeout (100ms..=5000ms).
    pub timeout: Duration,
    /// Maximum concurrent worker threads (1..=50).
    pub max_concurrency: usize,
    /// Inter-probe delay for rate limiting.
    pub rate_limit_delay: Option<Duration>,
}

impl Default for TcpScanConfig {
    fn default() -> Self {
        Self {
            // Default top common web and management ports
            ports: vec![
                80, 443, 8080, 8443, 22, 21, 25, 53, 110, 143, 993, 995, 3306, 5432, 6379, 8000,
            ],
            timeout: Duration::from_millis(1500),
            max_concurrency: 10,
            rate_limit_delay: Some(Duration::from_millis(5)),
        }
    }
}

impl TcpScanConfig {
    /// Creates a conservative scanner config with custom ports and bounds checking.
    pub fn new(
        ports: Vec<u16>,
        timeout_ms: u64,
        max_concurrency: usize,
    ) -> Result<Self, NetworkError> {
        if ports.is_empty() {
            return Err(NetworkError::TargetParse(
                "Port list cannot be empty".into(),
            ));
        }
        if ports.len() > 1024 {
            return Err(NetworkError::TargetParse(format!(
                "Port list exceeds maximum 1024 ports (requested: {})",
                ports.len()
            )));
        }
        if ports.contains(&0) {
            return Err(NetworkError::TargetParse(
                "Port 0 is reserved and invalid".into(),
            ));
        }

        let timeout = Duration::from_millis(timeout_ms.clamp(100, 5000));
        let max_concurrency = max_concurrency.clamp(1, 50);

        // Deduplicate ports while preserving order
        let mut seen = std::collections::HashSet::new();
        let mut deduped = Vec::new();
        for p in ports {
            if seen.insert(p) {
                deduped.push(p);
            }
        }

        Ok(Self {
            ports: deduped,
            timeout,
            max_concurrency,
            rate_limit_delay: Some(Duration::from_millis(5)),
        })
    }
}

/// Safe, rate-limited TCP perimeter discovery engine.
#[derive(Debug, Default)]
pub struct TcpScanner;

impl TcpScanner {
    /// Probes the specified ports on the pinned destination address.
    ///
    /// Uses the pre-validated pinned IP address exclusively.
    pub fn scan(
        pinned_target: &PinnedTarget,
        config: &TcpScanConfig,
        cancel_token: Option<Arc<AtomicBool>>,
    ) -> Result<Vec<PortScanResult>, NetworkError> {
        let ip = pinned_target.pinned_addr.ip();
        let mut results = Vec::with_capacity(config.ports.len());

        // Probe ports sequentially or in bounded chunks
        for &port in &config.ports {
            if let Some(ref cancel) = cancel_token {
                if cancel.load(Ordering::Relaxed) {
                    break;
                }
            }

            let addr = SocketAddr::new(ip, port);
            let start = Instant::now();

            let (status, diagnostic) = match TcpStream::connect_timeout(&addr, config.timeout) {
                Ok(stream) => {
                    // Immediately shut down the connection cleanly
                    let _ = stream.shutdown(Shutdown::Both);
                    (PortStatus::Open, None)
                }
                Err(err) => {
                    let kind = err.kind();
                    if kind == ErrorKind::ConnectionRefused {
                        (PortStatus::Closed, Some("Connection refused (RST)".into()))
                    } else if kind == ErrorKind::TimedOut || kind == ErrorKind::WouldBlock {
                        (PortStatus::Filtered, Some("Connection timed out".into()))
                    } else {
                        (PortStatus::Filtered, Some(format!("{err}")))
                    }
                }
            };

            let latency_ms = start.elapsed().as_millis() as u64;

            results.push(PortScanResult {
                port,
                status,
                latency_ms,
                diagnostic,
            });

            // Rate-limiting pause between probes
            if let Some(delay) = config.rate_limit_delay {
                thread::sleep(delay);
            }
        }

        Ok(results)
    }
}
