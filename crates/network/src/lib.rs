//! # OpenAudit Network
//!
//! Network perimeter scanning foundation providing canonical target parsing,
//! scope authorization, SSRF protection, and pinned DNS resolution.

pub mod error;
pub mod pinned;
pub mod redirect;
pub mod resolver;
pub mod scope;
pub mod target;

pub use error::NetworkError;
pub use pinned::PinnedTarget;
pub use redirect::RedirectValidator;
pub use resolver::{DnsResolver, SystemDnsResolver};
pub use scope::{IpClassification, ScopeDecision, TargetScope};
pub use target::{CanonicalTarget, TargetType};
