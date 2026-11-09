//! # OpenAudit Agent Library
//!
//! Exposes agent client and daemon communication infrastructure for integration
//! and outbound task execution.

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
