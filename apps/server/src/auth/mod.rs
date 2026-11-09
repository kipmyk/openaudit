//! Authentication and authorization subsystem.

pub mod middleware;
pub mod password;
pub mod rate_limit;
pub mod token;

pub use middleware::AuthenticatedUser;
pub use password::{hash_password, verify_password};
pub use rate_limit::LoginRateLimiter;
pub use token::{issue_token, verify_token, verify_token_with_fallbacks, TokenClaims};
