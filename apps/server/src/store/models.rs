//! Entity models and types for control plane persistence.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

/// Role-based access control classifications.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Role {
    Viewer = 0,
    Auditor = 1,
    Admin = 2,
}

impl Role {
    #[must_use]
    pub const fn can_manage_users(self) -> bool {
        matches!(self, Self::Admin)
    }

    #[must_use]
    pub const fn can_trigger_assessments(self) -> bool {
        matches!(self, Self::Admin | Self::Auditor)
    }

    #[must_use]
    pub const fn can_manage_assets(self) -> bool {
        matches!(self, Self::Admin | Self::Auditor)
    }

    #[must_use]
    pub const fn can_view_reports(self) -> bool {
        true
    }

    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Viewer => "viewer",
            Self::Auditor => "auditor",
            Self::Admin => "admin",
        }
    }

    /// Parses a string into a typed `Role`.
    ///
    /// # Errors
    ///
    /// Returns an error string if role name is unrecognized.
    pub fn parse(s: &str) -> Result<Self, String> {
        match s.to_lowercase().as_str() {
            "viewer" => Ok(Self::Viewer),
            "auditor" => Ok(Self::Auditor),
            "admin" => Ok(Self::Admin),
            other => Err(format!(
                "Unknown role '{other}'. Supported: viewer, auditor, admin"
            )),
        }
    }
}

/// Tenant organization record.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Organization {
    pub id: Uuid,
    pub slug: String,
    pub name: String,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

/// User account record.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct User {
    pub id: Uuid,
    pub org_id: Uuid,
    pub email: String,
    #[serde(skip_serializing)]
    pub password_hash: String,
    pub name: String,
    pub role: Role,
    pub is_active: bool,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

/// Asset inventory item.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Asset {
    pub id: Uuid,
    pub org_id: Uuid,
    pub name: String,
    pub asset_type: String,
    pub target: String,
    pub criticality: String,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

/// State of an asynchronous assessment job.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum JobStatus {
    Pending,
    Running,
    Completed,
    Failed,
    Cancelled,
}

impl JobStatus {
    #[must_use]
    pub const fn is_terminal(self) -> bool {
        matches!(self, Self::Completed | Self::Failed | Self::Cancelled)
    }

    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Pending => "pending",
            Self::Running => "running",
            Self::Completed => "completed",
            Self::Failed => "failed",
            Self::Cancelled => "cancelled",
        }
    }

    /// Parses string representation into `JobStatus`.
    ///
    /// # Errors
    ///
    /// Returns an error if string is not a valid status.
    pub fn parse(s: &str) -> Result<Self, String> {
        match s.to_lowercase().as_str() {
            "pending" => Ok(Self::Pending),
            "running" => Ok(Self::Running),
            "completed" => Ok(Self::Completed),
            "failed" => Ok(Self::Failed),
            "cancelled" => Ok(Self::Cancelled),
            other => Err(format!("Unknown job status '{other}'")),
        }
    }
}

/// Status classification of an enrolled agent.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AgentStatus {
    Pending,
    Active,
    Revoked,
}

impl AgentStatus {
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Pending => "pending",
            Self::Active => "active",
            Self::Revoked => "revoked",
        }
    }

    /// Parses string representation into `AgentStatus`.
    ///
    /// # Errors
    ///
    /// Returns an error if string is not a valid status.
    pub fn parse(s: &str) -> Result<Self, String> {
        match s.to_lowercase().as_str() {
            "pending" => Ok(Self::Pending),
            "active" => Ok(Self::Active),
            "revoked" => Ok(Self::Revoked),
            other => Err(format!("Unknown agent status '{other}'")),
        }
    }
}

/// Enrolled agent record.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct EnrolledAgent {
    pub id: Uuid,
    pub org_id: Uuid,
    pub machine_id: String,
    pub hostname: String,
    pub agent_version: String,
    pub status: AgentStatus,
    #[serde(skip_serializing)]
    pub auth_token_hash: String,
    pub public_identity: String,
    pub capabilities: String,
    pub last_seen_at: DateTime<Utc>,
    pub enrolled_at: DateTime<Utc>,
    pub revoked_at: Option<DateTime<Utc>>,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

/// One-time agent enrollment token record.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AgentEnrollmentToken {
    pub id: Uuid,
    pub org_id: Uuid,
    #[serde(skip_serializing)]
    pub token_secret: String,
    pub machine_id: Option<String>,
    pub challenge_nonce: String,
    pub expires_at: DateTime<Utc>,
    pub used_at: Option<DateTime<Utc>>,
    pub created_at: DateTime<Utc>,
}

/// Asynchronous assessment job record.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AssessmentJob {
    pub id: Uuid,
    pub org_id: Uuid,
    pub asset_id: Option<Uuid>,
    pub target: String,
    pub assessment_type: String,
    pub profile: String,
    pub status: JobStatus,
    pub summary_json: Option<String>,
    pub error_message: Option<String>,
    pub started_at: Option<DateTime<Utc>>,
    pub completed_at: Option<DateTime<Utc>>,
    pub created_at: DateTime<Utc>,
    pub assigned_agent_id: Option<Uuid>,
    pub lease_expires_at: Option<DateTime<Utc>>,
    pub execution_source: String,
    pub rules_subset: Option<String>,
}

/// Discovered security finding record.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AssessmentFinding {
    pub id: Uuid,
    pub org_id: Uuid,
    pub job_id: Uuid,
    pub rule_id: String,
    pub severity: String,
    pub confidence: String,
    pub title: String,
    pub endpoint: String,
    pub evidence: String,
    pub recommendation: String,
    pub created_at: DateTime<Utc>,
}

/// Parameters for creating a new finding.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NewFinding {
    pub rule_id: String,
    pub severity: String,
    pub confidence: String,
    pub title: String,
    pub endpoint: String,
    pub evidence: String,
    pub recommendation: String,
}

/// Recurring assessment schedule record.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AssessmentSchedule {
    pub id: Uuid,
    pub org_id: Uuid,
    pub asset_id: Option<Uuid>,
    pub name: String,
    pub cron_expression: String,
    pub target: String,
    pub assessment_type: String,
    pub profile: String,
    pub is_active: bool,
    pub last_run_at: Option<DateTime<Utc>>,
    pub next_run_at: Option<DateTime<Utc>>,
    pub created_at: DateTime<Utc>,
}

/// Revoked authentication token record.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RevokedToken {
    pub jti: Uuid,
    pub expires_at: DateTime<Utc>,
    pub revoked_at: DateTime<Utc>,
}
