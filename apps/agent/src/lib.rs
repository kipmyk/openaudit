//! # OpenAudit Agent Library
//!
//! Exposes agent client and daemon communication infrastructure for integration
//! and outbound task execution.
//!
//! # Examples
//!
//! ```
//! use openaudit_agent::AgentDaemonConfig;
//! use std::path::PathBuf;
//!
//! let cfg = AgentDaemonConfig {
//!     server_url: "https://audit.example.com".to_string(),
//!     state_dir: PathBuf::from("/var/lib/openaudit-agent"),
//!     poll_interval_secs: 30,
//!     heartbeat_interval_secs: 60,
//!     max_backoff_secs: 300,
//! };
//! assert_eq!(cfg.poll_interval_secs, 30);
//! ```

#![allow(
    clippy::missing_errors_doc,
    clippy::significant_drop_tightening,
    clippy::too_many_lines,
    clippy::struct_excessive_bools,
    clippy::result_large_err,
    clippy::must_use_candidate,
    clippy::doc_markdown,
    clippy::cast_possible_truncation,
    clippy::cast_possible_wrap,
    clippy::too_many_arguments,
    clippy::unused_async,
    clippy::unused_self,
    clippy::unnecessary_wraps,
    clippy::missing_const_for_fn
)]

pub mod client;

pub use client::{
    AgentClient, AgentDaemonConfig, AgentFindingPayload, DispatchedJob, EnrolledCredentials,
};
