//! Durable persistence layer for control plane entities with strict tenant isolation.

pub mod models;
pub mod sqlite;

use chrono::{DateTime, Utc};
use std::fmt;
use uuid::Uuid;

pub use models::{
    AssessmentFinding, AssessmentJob, AssessmentSchedule, Asset, JobStatus, NewFinding,
    Organization, Role, User,
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
pub trait ControlPlaneStore: Send + Sync + 'static {
    /// Returns true if the underlying persistence engine is connected and healthy.
    fn is_healthy(&self) -> bool;

    // --- Organizations ---
    fn create_organization(&self, name: &str, slug: &str) -> Result<Organization, StoreError>;
    fn get_organization(&self, id: Uuid) -> Result<Option<Organization>, StoreError>;
    fn get_organization_by_slug(&self, slug: &str) -> Result<Option<Organization>, StoreError>;

    // --- Users ---
    fn create_user(
        &self,
        org_id: Uuid,
        email: &str,
        password_hash: &str,
        name: &str,
        role: Role,
    ) -> Result<User, StoreError>;
    fn get_user_by_email(&self, email: &str) -> Result<Option<User>, StoreError>;
    fn get_user_by_id(&self, org_id: Uuid, user_id: Uuid) -> Result<Option<User>, StoreError>;
    fn list_users(&self, org_id: Uuid) -> Result<Vec<User>, StoreError>;

    // --- Assets ---
    fn create_asset(
        &self,
        org_id: Uuid,
        name: &str,
        asset_type: &str,
        target: &str,
        criticality: &str,
    ) -> Result<Asset, StoreError>;
    fn get_asset(&self, org_id: Uuid, id: Uuid) -> Result<Option<Asset>, StoreError>;
    fn list_assets(&self, org_id: Uuid) -> Result<Vec<Asset>, StoreError>;
    fn delete_asset(&self, org_id: Uuid, id: Uuid) -> Result<bool, StoreError>;

    // --- Assessment Jobs ---
    fn create_job(
        &self,
        org_id: Uuid,
        asset_id: Option<Uuid>,
        target: &str,
        assessment_type: &str,
        profile: &str,
    ) -> Result<AssessmentJob, StoreError>;
    fn get_job(&self, org_id: Uuid, id: Uuid) -> Result<Option<AssessmentJob>, StoreError>;
    fn update_job_status(
        &self,
        org_id: Uuid,
        id: Uuid,
        status: JobStatus,
        summary_json: Option<&str>,
        error_message: Option<&str>,
    ) -> Result<(), StoreError>;
    fn list_jobs(&self, org_id: Uuid, limit: usize) -> Result<Vec<AssessmentJob>, StoreError>;

    // --- Assessment Findings ---
    fn create_findings(
        &self,
        org_id: Uuid,
        job_id: Uuid,
        findings: &[NewFinding],
    ) -> Result<(), StoreError>;
    fn list_findings(
        &self,
        org_id: Uuid,
        job_id: Option<Uuid>,
        min_severity: Option<&str>,
    ) -> Result<Vec<AssessmentFinding>, StoreError>;

    // --- Assessment Schedules ---
    fn create_schedule(
        &self,
        org_id: Uuid,
        asset_id: Option<Uuid>,
        name: &str,
        cron_expression: &str,
        target: &str,
        assessment_type: &str,
        profile: &str,
    ) -> Result<AssessmentSchedule, StoreError>;
    fn list_schedules(&self, org_id: Uuid) -> Result<Vec<AssessmentSchedule>, StoreError>;
    fn get_due_schedules(&self) -> Result<Vec<AssessmentSchedule>, StoreError>;
    fn update_schedule_run_state(
        &self,
        schedule_id: Uuid,
        last_run: DateTime<Utc>,
        next_run: Option<DateTime<Utc>>,
    ) -> Result<(), StoreError>;
}
