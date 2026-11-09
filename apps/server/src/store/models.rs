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
    pub rules_evaluated: Option<String>,
    pub engine_version: String,
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
    pub fingerprint: Option<String>,
    pub managed_finding_id: Option<Uuid>,
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

/// Finding lifecycle status across repeated assessments.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum FindingStatus {
    Open,
    Acknowledged,
    InProgress,
    Resolved,
    AcceptedRisk,
    Reopened,
}

impl FindingStatus {
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Open => "open",
            Self::Acknowledged => "acknowledged",
            Self::InProgress => "in_progress",
            Self::Resolved => "resolved",
            Self::AcceptedRisk => "accepted_risk",
            Self::Reopened => "reopened",
        }
    }

    /// Parses a string into a FindingStatus.
    ///
    /// # Errors
    /// Returns error string on unrecognized status.
    pub fn parse(s: &str) -> Result<Self, String> {
        match s.to_ascii_lowercase().as_str() {
            "open" => Ok(Self::Open),
            "acknowledged" => Ok(Self::Acknowledged),
            "in_progress" => Ok(Self::InProgress),
            "resolved" => Ok(Self::Resolved),
            "accepted_risk" => Ok(Self::AcceptedRisk),
            "reopened" => Ok(Self::Reopened),
            other => Err(format!("Unknown finding status: {other}")),
        }
    }
}

/// Classification of how a finding was resolved.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ResolutionType {
    VerifiedRemediated,
    ManuallyResolved,
    AcceptedRisk,
}

impl ResolutionType {
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::VerifiedRemediated => "verified_remediated",
            Self::ManuallyResolved => "manually_resolved",
            Self::AcceptedRisk => "accepted_risk",
        }
    }

    /// Parses a string into a ResolutionType.
    ///
    /// # Errors
    /// Returns error string on unrecognized resolution type.
    pub fn parse(s: &str) -> Result<Self, String> {
        match s.to_ascii_lowercase().as_str() {
            "verified_remediated" => Ok(Self::VerifiedRemediated),
            "manually_resolved" => Ok(Self::ManuallyResolved),
            "accepted_risk" => Ok(Self::AcceptedRisk),
            other => Err(format!("Unknown resolution type: {other}")),
        }
    }
}

/// Durable managed security finding identity across repeated assessments.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ManagedFinding {
    pub id: Uuid,
    pub org_id: Uuid,
    pub asset_id: Option<Uuid>,
    pub fingerprint: String,
    pub rule_id: String,
    pub domain: String,
    pub endpoint: String,
    pub title: String,
    pub severity: String,
    pub confidence: String,
    pub status: FindingStatus,
    pub resolution_type: Option<ResolutionType>,
    pub first_observed_at: DateTime<Utc>,
    pub last_observed_at: DateTime<Utc>,
    pub first_job_id: Uuid,
    pub last_job_id: Uuid,
    pub occurrence_count: i32,
    pub assigned_owner: Option<String>,
    pub due_date: Option<DateTime<Utc>>,
    pub remediation_notes: Option<String>,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

/// Status transition history record for a managed finding.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FindingStatusHistory {
    pub id: Uuid,
    pub finding_id: Uuid,
    pub old_status: FindingStatus,
    pub new_status: FindingStatus,
    pub resolution_type: Option<ResolutionType>,
    pub changed_by_user_id: Option<Uuid>,
    pub job_id: Option<Uuid>,
    pub comment: Option<String>,
    pub created_at: DateTime<Utc>,
}

/// Deterministically computes the SHA-256 finding fingerprint.
///
/// Binds the tenant, normalized target/asset, assessment domain, rule ID, and endpoint.
/// Note: mutable evidence text and timestamps are deliberately excluded to ensure stable identity.
#[must_use]
pub fn compute_finding_fingerprint(
    org_id: Uuid,
    target_or_asset: &str,
    domain: &str,
    rule_id: &str,
    endpoint: &str,
) -> String {
    use sha2::{Digest, Sha256};
    let mut hasher = Sha256::new();
    let norm_target = target_or_asset.trim().to_lowercase();
    let norm_domain = domain.trim().to_lowercase();
    let norm_rule = rule_id.trim().to_lowercase();
    let norm_endpoint = endpoint.trim().to_lowercase();
    hasher.update(
        format!("{org_id}:{norm_target}:{norm_domain}:{norm_rule}:{norm_endpoint}").as_bytes(),
    );
    let res = hasher.finalize();
    let mut s = String::with_capacity(64);
    for b in res {
        use std::fmt::Write;
        let _ = write!(s, "{b:02x}");
    }
    s
}

/// Comparison analysis between two assessments of the same asset.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AssessmentComparison {
    pub base_job_id: Uuid,
    pub target_job_id: Uuid,
    pub asset_id: Option<Uuid>,
    pub target: String,
    pub base_created_at: DateTime<Utc>,
    pub target_created_at: DateTime<Utc>,
    pub base_rules_evaluated: Vec<String>,
    pub target_rules_evaluated: Vec<String>,
    pub rules_added: Vec<String>,
    pub rules_removed: Vec<String>,
    pub coverage_ratio: f64,
    pub coverage_notes: String,
    pub new_findings: Vec<AssessmentFinding>,
    pub persistent_findings: Vec<AssessmentFinding>,
    pub resolved_findings: Vec<ManagedFinding>,
    pub unverified_omissions: Vec<AssessmentFinding>,
    pub reopened_findings: Vec<AssessmentFinding>,
    pub severity_changes: Vec<SeverityChange>,
}

/// Detail on finding severity change between assessments.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SeverityChange {
    pub fingerprint: String,
    pub rule_id: String,
    pub endpoint: String,
    pub base_severity: String,
    pub target_severity: String,
}

/// Organization or asset-level security posture summary metrics.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SecurityPostureSummary {
    pub org_id: Uuid,
    pub calculated_at: DateTime<Utc>,
    pub total_assets: usize,
    pub assessed_assets: usize,
    pub stale_assets: usize,
    pub total_active_findings: usize,
    pub findings_by_severity: SeverityBreakdown,
    pub findings_by_status: StatusBreakdown,
    pub verified_remediations_count: usize,
    pub manual_resolutions_count: usize,
    pub accepted_risks_count: usize,
    pub total_assessments_completed: usize,
    pub total_assessments_failed: usize,
}

/// Breakdown of findings by severity rank.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct SeverityBreakdown {
    pub critical: usize,
    pub high: usize,
    pub medium: usize,
    pub low: usize,
    pub info: usize,
}

/// Breakdown of findings by lifecycle status.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct StatusBreakdown {
    pub open: usize,
    pub acknowledged: usize,
    pub in_progress: usize,
    pub resolved: usize,
    pub accepted_risk: usize,
    pub reopened: usize,
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
