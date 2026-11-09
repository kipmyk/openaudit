//! Server configuration, environment validation, and secure defaults.

use std::env;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::path::PathBuf;

/// Execution environment classification.
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ServerEnvironment {
    Development,
    Test,
    Staging,
    Production,
}

impl ServerEnvironment {
    #[must_use]
    pub const fn is_production(self) -> bool {
        matches!(self, Self::Production)
    }
}

/// Comprehensive control-plane server configuration.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct ServerConfig {
    /// Operating environment.
    pub environment: ServerEnvironment,
    /// Network socket binding address (default: 127.0.0.1:8080).
    pub bind_addr: SocketAddr,
    /// File storage directory root.
    pub data_dir: PathBuf,
    /// Optional PostgreSQL database connection string (if None, embedded storage is used).
    pub database_url: Option<String>,
    /// Cryptographic signing secret for authentication tokens (min 32 bytes).
    pub secret_key: String,
    /// Fallback secrets accepted during key rotation.
    pub fallback_secret_keys: Vec<String>,
    /// Permitted CORS origins for API requests.
    pub allowed_origins: Vec<String>,
    /// Global HTTP request timeout in seconds.
    pub request_timeout_secs: u64,
    /// Maximum permitted request body size in bytes (default: 2 MB).
    pub max_body_size_bytes: usize,
    /// Bounded concurrency limit for active background assessment workers.
    pub max_concurrent_jobs: usize,
    /// Maximum permitted scanned ports per perimeter assessment request.
    pub max_ports_per_scan: usize,
}

impl Default for ServerConfig {
    fn default() -> Self {
        Self {
            environment: ServerEnvironment::Development,
            bind_addr: SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 8080),
            data_dir: PathBuf::from("./data"),
            database_url: None,
            secret_key: "openaudit-insecure-dev-secret-do-not-use-in-prod".to_string(),
            fallback_secret_keys: Vec::new(),
            allowed_origins: vec![
                "http://localhost:3000".to_string(),
                "http://127.0.0.1:3000".to_string(),
            ],
            request_timeout_secs: 30,
            max_body_size_bytes: 2 * 1024 * 1024, // 2MB
            max_concurrent_jobs: 8,
            max_ports_per_scan: 1000,
        }
    }
}

impl ServerConfig {
    /// Constructs a configuration initialized from environment variables with safe defaults.
    ///
    /// # Errors
    ///
    /// Returns an error if any environment variable has an invalid format or if production
    /// validation checks fail.
    pub fn from_env() -> Result<Self, String> {
        let mut config = Self::default();

        if let Ok(env_str) = env::var("OPENAUDIT_ENV") {
            config.environment = match env_str.to_lowercase().as_str() {
                "prod" | "production" => ServerEnvironment::Production,
                "stage" | "staging" => ServerEnvironment::Staging,
                "test" | "testing" => ServerEnvironment::Test,
                "dev" | "development" => ServerEnvironment::Development,
                other => {
                    return Err(format!(
                        "Invalid OPENAUDIT_ENV '{other}'. Expected: development, test, staging, production"
                    ));
                }
            };
        }

        if let Ok(addr_str) = env::var("OPENAUDIT_BIND_ADDR") {
            config.bind_addr = addr_str
                .parse::<SocketAddr>()
                .map_err(|e| format!("Invalid OPENAUDIT_BIND_ADDR '{addr_str}': {e}"))?;
        } else if let Ok(port_str) = env::var("OPENAUDIT_PORT") {
            let port = port_str
                .parse::<u16>()
                .map_err(|e| format!("Invalid OPENAUDIT_PORT '{port_str}': {e}"))?;
            config.bind_addr.set_port(port);
        }

        if let Ok(dir_str) = env::var("OPENAUDIT_DATA_DIR") {
            config.data_dir = PathBuf::from(dir_str);
        }

        if let Ok(db_url) = env::var("DATABASE_URL") {
            if !db_url.trim().is_empty() {
                config.database_url = Some(db_url.trim().to_string());
            }
        }

        if let Ok(secret) = env::var("OPENAUDIT_SECRET_KEY") {
            config.secret_key = secret;
        }

        if let Ok(fallbacks) = env::var("OPENAUDIT_FALLBACK_SECRETS") {
            config.fallback_secret_keys = fallbacks
                .split(',')
                .map(str::trim)
                .filter(|s| !s.is_empty())
                .map(ToString::to_string)
                .collect();
        }

        if let Ok(origins) = env::var("OPENAUDIT_ALLOWED_ORIGINS") {
            config.allowed_origins = origins
                .split(',')
                .map(str::trim)
                .filter(|s| !s.is_empty())
                .map(ToString::to_string)
                .collect();
        }

        if let Ok(timeout_str) = env::var("OPENAUDIT_REQUEST_TIMEOUT_SECS") {
            config.request_timeout_secs = timeout_str.parse::<u64>().map_err(|e| {
                format!("Invalid OPENAUDIT_REQUEST_TIMEOUT_SECS '{timeout_str}': {e}")
            })?;
        }

        if let Ok(jobs_str) = env::var("OPENAUDIT_MAX_CONCURRENT_JOBS") {
            config.max_concurrent_jobs = jobs_str
                .parse::<usize>()
                .map_err(|e| format!("Invalid OPENAUDIT_MAX_CONCURRENT_JOBS '{jobs_str}': {e}"))?;
        }

        config.validate()?;
        Ok(config)
    }

    /// Enforces security and operational constraints on the configuration.
    ///
    /// # Errors
    ///
    /// Returns an error if production invariants or operational bounds are violated.
    pub fn validate(&self) -> Result<(), String> {
        if self.request_timeout_secs == 0 {
            return Err("request_timeout_secs cannot be zero".into());
        }

        if self.max_concurrent_jobs == 0 || self.max_concurrent_jobs > 100 {
            return Err("max_concurrent_jobs must be between 1 and 100".into());
        }

        if self.max_ports_per_scan == 0 || self.max_ports_per_scan > 5000 {
            return Err("max_ports_per_scan must be between 1 and 5000".into());
        }

        if self.environment.is_production() {
            if self.secret_key.contains("dev-secret") || self.secret_key.len() < 32 {
                return Err(
                    "Production configuration failure: OPENAUDIT_SECRET_KEY must be a cryptographically strong secret of at least 32 bytes and cannot contain default development strings."
                        .into(),
                );
            }

            if self.bind_addr.ip().is_unspecified()
                && env::var("OPENAUDIT_ALLOW_UNSPECIFIED_BIND").is_err()
            {
                return Err(
                    "Production configuration failure: binding to 0.0.0.0 (all interfaces) requires explicit acknowledgment via OPENAUDIT_ALLOW_UNSPECIFIED_BIND=1."
                        .into(),
                );
            }
        }

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_default_config_is_valid_for_dev() {
        let config = ServerConfig::default();
        assert!(config.validate().is_ok());
        assert_eq!(config.environment, ServerEnvironment::Development);
        assert_eq!(config.bind_addr.port(), 8080);
    }

    #[test]
    fn test_production_rejects_default_secret() {
        let config = ServerConfig {
            environment: ServerEnvironment::Production,
            ..Default::default()
        };
        let err = config.validate().unwrap_err();
        assert!(err.contains("OPENAUDIT_SECRET_KEY"));
    }

    #[test]
    fn test_production_rejects_short_secret() {
        let config = ServerConfig {
            environment: ServerEnvironment::Production,
            secret_key: "too-short-secret".into(),
            ..Default::default()
        };
        let err = config.validate().unwrap_err();
        assert!(err.contains("at least 32 bytes"));
    }

    #[test]
    fn test_production_valid_with_strong_secret() {
        let config = ServerConfig {
            environment: ServerEnvironment::Production,
            secret_key: "a_super_strong_cryptographically_secure_random_production_secret_32bytes"
                .into(),
            ..Default::default()
        };
        assert!(config.validate().is_ok());
    }
}
