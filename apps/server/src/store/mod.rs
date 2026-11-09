//! Durable persistence layer for control plane entities with strict tenant isolation.

pub mod models;
pub mod postgres;
pub mod sqlite;

use chrono::{DateTime, Utc};
use std::fmt;
use uuid::Uuid;

pub use models::{
    AgentEnrollmentToken, AgentStatus, AssessmentFinding, AssessmentJob, AssessmentSchedule, Asset,
    EnrolledAgent, JobStatus, NewFinding, Organization, RevokedToken, Role, User,
};

/// Errors originating from the persistence layer.
#[derive(Debug)]
pub enum StoreError {
    Database(String),
    NotFound(String),
    Conflict(String),
    Unauthorized(String),
}

impl fmt::Display for StoreError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Database(msg) => write!(f, "database error: {msg}"),
            Self::NotFound(msg) => write!(f, "entity not found: {msg}"),
            Self::Conflict(msg) => write!(f, "conflict: {msg}"),
            Self::Unauthorized(msg) => write!(f, "unauthorized access: {msg}"),
        }
    }
}

impl std::error::Error for StoreError {}

/// Authoritative interface for control-plane persistence.
///
/// Every query or mutation touching tenant data REQUIRES an explicit `org_id`
/// to guarantee tenant isolation at the data access layer.
#[async_trait::async_trait]
pub trait ControlPlaneStore: Send + Sync + 'static {
    /// Returns true if the underlying persistence engine is connected and healthy.
    async fn is_healthy(&self) -> bool;

    // --- Atomic Bootstrap ---
    async fn bootstrap_admin(
        &self,
        org_name: &str,
        org_slug: &str,
        admin_name: &str,
        admin_email: &str,
        password_hash: &str,
    ) -> Result<(Organization, User), StoreError>;

    // --- Organizations ---
    async fn create_organization(&self, name: &str, slug: &str)
        -> Result<Organization, StoreError>;
    async fn get_organization(&self, id: Uuid) -> Result<Option<Organization>, StoreError>;
    async fn get_organization_by_slug(
        &self,
        slug: &str,
    ) -> Result<Option<Organization>, StoreError>;

    // --- Users ---
    async fn create_user(
        &self,
        org_id: Uuid,
        email: &str,
        password_hash: &str,
        name: &str,
        role: Role,
    ) -> Result<User, StoreError>;
    async fn get_user_by_email(&self, email: &str) -> Result<Option<User>, StoreError>;
    async fn get_user_by_id(&self, org_id: Uuid, user_id: Uuid)
        -> Result<Option<User>, StoreError>;
    async fn list_users(&self, org_id: Uuid) -> Result<Vec<User>, StoreError>;

    // --- Assets ---
    async fn create_asset(
        &self,
        org_id: Uuid,
        name: &str,
        asset_type: &str,
        target: &str,
        criticality: &str,
    ) -> Result<Asset, StoreError>;
    async fn get_asset(&self, org_id: Uuid, id: Uuid) -> Result<Option<Asset>, StoreError>;
    async fn list_assets(&self, org_id: Uuid) -> Result<Vec<Asset>, StoreError>;
    async fn delete_asset(&self, org_id: Uuid, id: Uuid) -> Result<bool, StoreError>;

    // --- Assessment Jobs ---
    async fn create_job(
        &self,
        org_id: Uuid,
        asset_id: Option<Uuid>,
        target: &str,
        assessment_type: &str,
        profile: &str,
    ) -> Result<AssessmentJob, StoreError>;
    async fn get_job(&self, org_id: Uuid, id: Uuid) -> Result<Option<AssessmentJob>, StoreError>;
    async fn update_job_status(
        &self,
        org_id: Uuid,
        id: Uuid,
        status: JobStatus,
        summary_json: Option<&str>,
        error_message: Option<&str>,
    ) -> Result<(), StoreError>;
    async fn list_jobs(&self, org_id: Uuid, limit: usize)
        -> Result<Vec<AssessmentJob>, StoreError>;

    // --- Assessment Findings ---
    async fn create_findings(
        &self,
        org_id: Uuid,
        job_id: Uuid,
        findings: &[NewFinding],
    ) -> Result<(), StoreError>;
    async fn list_findings(
        &self,
        org_id: Uuid,
        job_id: Option<Uuid>,
        min_severity: Option<&str>,
    ) -> Result<Vec<AssessmentFinding>, StoreError>;

    // --- Assessment Schedules ---
    async fn create_schedule(
        &self,
        org_id: Uuid,
        asset_id: Option<Uuid>,
        name: &str,
        cron_expression: &str,
        target: &str,
        assessment_type: &str,
        profile: &str,
    ) -> Result<AssessmentSchedule, StoreError>;
    async fn list_schedules(&self, org_id: Uuid) -> Result<Vec<AssessmentSchedule>, StoreError>;
    async fn get_due_schedules(&self) -> Result<Vec<AssessmentSchedule>, StoreError>;
    async fn update_schedule_run_state(
        &self,
        schedule_id: Uuid,
        last_run: DateTime<Utc>,
        next_run: Option<DateTime<Utc>>,
    ) -> Result<(), StoreError>;

    // --- Token Revocation ---
    async fn revoke_token(&self, jti: Uuid, expires_at: DateTime<Utc>) -> Result<(), StoreError>;
    async fn is_token_revoked(&self, jti: Uuid) -> Result<bool, StoreError>;
    async fn clean_expired_revocations(&self) -> Result<usize, StoreError>;

    // --- Interrupted Job Recovery ---
    async fn recover_interrupted_jobs(&self) -> Result<usize, StoreError>;

    // --- Agent Enrollment & Management ---
    async fn issue_agent_enrollment_token(
        &self,
        org_id: Uuid,
        token_secret: &str,
        machine_id: Option<&str>,
        challenge_nonce: &str,
        expires_at: DateTime<Utc>,
    ) -> Result<AgentEnrollmentToken, StoreError>;
    async fn get_agent_enrollment_token(
        &self,
        token_id: Uuid,
    ) -> Result<Option<AgentEnrollmentToken>, StoreError>;
    async fn consume_enrollment_token(&self, token_id: Uuid) -> Result<(), StoreError>;
    async fn enroll_agent(
        &self,
        org_id: Uuid,
        machine_id: &str,
        hostname: &str,
        agent_version: &str,
        auth_token_hash: &str,
        public_identity: &str,
        capabilities: &str,
    ) -> Result<EnrolledAgent, StoreError>;
    async fn get_agent_by_id(
        &self,
        org_id: Uuid,
        agent_id: Uuid,
    ) -> Result<Option<EnrolledAgent>, StoreError>;
    async fn get_agent_by_auth_hash(
        &self,
        auth_token_hash: &str,
    ) -> Result<Option<EnrolledAgent>, StoreError>;
    async fn list_agents(&self, org_id: Uuid) -> Result<Vec<EnrolledAgent>, StoreError>;
    async fn update_agent_status(
        &self,
        org_id: Uuid,
        agent_id: Uuid,
        status: AgentStatus,
    ) -> Result<(), StoreError>;
    async fn update_agent_heartbeat(
        &self,
        agent_id: Uuid,
        last_seen_at: DateTime<Utc>,
    ) -> Result<(), StoreError>;
    async fn rotate_agent_credential(
        &self,
        agent_id: Uuid,
        new_auth_hash: &str,
    ) -> Result<(), StoreError>;

    // --- Distributed Job Claim & Dispatch ---
    async fn claim_next_pending_job(
        &self,
        agent_id: Uuid,
        org_id: Uuid,
        lease_duration_secs: i64,
    ) -> Result<Option<AssessmentJob>, StoreError>;
    async fn renew_job_lease(
        &self,
        agent_id: Uuid,
        job_id: Uuid,
        lease_duration_secs: i64,
    ) -> Result<bool, StoreError>;
    async fn complete_agent_job(
        &self,
        agent_id: Uuid,
        job_id: Uuid,
        org_id: Uuid,
        summary_json: Option<&str>,
        findings: &[NewFinding],
    ) -> Result<(), StoreError>;
    async fn fail_agent_job(
        &self,
        agent_id: Uuid,
        job_id: Uuid,
        org_id: Uuid,
        error_message: &str,
    ) -> Result<(), StoreError>;
}
