use thiserror::Error;

#[derive(Debug, Error)]
pub enum NetworkError {
    #[error("Target parse error: {0}")]
    TargetParse(String),

    #[error("Scope violation: {0}")]
    ScopeViolation(String),

    #[error("SSRF violation: destination {0} is in prohibited scope")]
    SsrfViolation(String),

    #[error("DNS resolution error: {0}")]
    DnsResolution(String),

    #[error("Redirect violation: {0}")]
    RedirectViolation(String),

    #[error("Connection error: {0}")]
    Connection(String),
}
