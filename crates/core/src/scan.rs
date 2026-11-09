//! Scan execution lifecycle, state transitions, and job queue models.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::fmt;

use crate::error::DomainError;
use crate::id::{AssetId, OrganizationId, ScanId, ScanJobId};
use crate::severity::Severity;

/// Classification of the assessment boundary and execution methodology.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Default, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AssessmentType {
    /// In-process evaluation of local operating system controls, users, services, and kernel configuration.
    #[default]
    LocalHostAssessment,
    /// Agentless, non-destructive network evaluation of observable services, open ports, TLS, and HTTP headers.
    RemoteNetworkAssessment,
    /// Remote operating system assessment performed over an authorized connection (e.g. `SSH` or `WinRM`).
    AuthenticatedRemoteHostAssessment,
    /// Continuous or scheduled host assessment executed locally by an enrolled, attested OpenAudit agent.
    EnrolledAgentHostAssessment,
}

impl AssessmentType {
    /// Returns the canonical human-readable display name for this assessment type.
    #[must_use]
    pub const fn display_name(&self) -> &'static str {
        match self {
            Self::LocalHostAssessment => "Local Host Assessment",
            Self::RemoteNetworkAssessment => "Remote Network Assessment",
            Self::AuthenticatedRemoteHostAssessment => "Authenticated Remote Host Assessment",
            Self::EnrolledAgentHostAssessment => "Enrolled Agent Host Assessment",
        }
    }

    /// Returns whether this assessment type inspects internal operating system configurations.
    ///
    /// An IP address or agentless network assessment can never inspect internal OS settings.
    #[must_use]
    pub const fn provides_operating_system_audit(&self) -> bool {
        match self {
            Self::LocalHostAssessment
            | Self::AuthenticatedRemoteHostAssessment
            | Self::EnrolledAgentHostAssessment => true,
            Self::RemoteNetworkAssessment => false,
        }
    }
}

/// How the scan was initiated.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Default, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum TriggerType {
    /// Manually invoked by an authorized operator.
    #[default]
    Manual,
    /// Automated recurring cron or scheduled trigger.
    Scheduled,
}

/// Lifecycle execution state of an audit scan.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Default, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum ScanStatus {
    /// Scan has been scheduled or enqueued, waiting to start.
    #[default]
    Pending,
    /// Scan is actively executing checks across assigned targets.
    Running,
    /// Scan completed all checks successfully.
    Completed,
    /// Scan encountered an unrecoverable failure.
    Failed,
    /// Scan was cancelled by an operator prior to completion.
    Cancelled,
}

impl ScanStatus {
    /// Returns whether this state is terminal (no further transitions permitted).
    #[must_use]
    pub const fn is_terminal(&self) -> bool {
        matches!(self, Self::Completed | Self::Failed | Self::Cancelled)
    }
}

/// Aggregate findings count by severity.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
pub struct ScanSummary {
    /// Total critical-severity findings.
    pub critical: u32,
    /// Total high-severity findings.
    pub high: u32,
    /// Total medium-severity findings.
    pub medium: u32,
    /// Total low-severity findings.
    pub low: u32,
    /// Total informational findings.
    pub info: u32,
}

impl ScanSummary {
    /// Increments the finding counter corresponding to the given severity.
    pub fn record(&mut self, severity: Severity) {
        match severity {
            Severity::Critical => self.critical += 1,
            Severity::High => self.high += 1,
            Severity::Medium => self.medium += 1,
            Severity::Low => self.low += 1,
            Severity::Info => self.info += 1,
        }
    }

    /// Returns the grand total count of all findings.
    #[must_use]
    pub const fn total(&self) -> u32 {
        self.critical + self.high + self.medium + self.low + self.info
    }
}

/// A high-level audit scan execution session.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Scan {
    /// Unique identifier for this scan.
    pub id: ScanId,
    /// Owning organization (tenant boundary).
    pub organization_id: OrganizationId,
    /// How this scan was initiated.
    pub trigger: TriggerType,
    /// Current lifecycle state.
    pub status: ScanStatus,
    /// Summary counts of findings discovered.
    pub summary: ScanSummary,
    /// Timestamp when execution commenced.
    pub started_at: Option<DateTime<Utc>>,
    /// Timestamp when execution finished (success, failure, or cancellation).
    pub completed_at: Option<DateTime<Utc>>,
    /// Timestamp when this scan was created.
    pub created_at: DateTime<Utc>,
}

impl Scan {
    /// Constructs a new [`Scan`] in `Pending` state.
    #[must_use]
    pub fn new(organization_id: OrganizationId, trigger: TriggerType) -> Self {
        Self {
            id: ScanId::new(),
            organization_id,
            trigger,
            status: ScanStatus::Pending,
            summary: ScanSummary::default(),
            started_at: None,
            completed_at: None,
            created_at: Utc::now(),
        }
    }

    /// Transitions scan state from `Pending` to `Running`.
    ///
    /// # Errors
    /// Returns [`DomainError::InvalidStateTransition`] if not currently `Pending`.
    pub fn start(&mut self) -> Result<(), DomainError> {
        if self.status != ScanStatus::Pending {
            return Err(DomainError::InvalidStateTransition {
                from: format!("{:?}", self.status),
                to: "Running".to_string(),
            });
        }
        self.status = ScanStatus::Running;
        self.started_at = Some(Utc::now());
        Ok(())
    }

    /// Transitions scan state to `Completed`.
    ///
    /// # Errors
    /// Returns [`DomainError::InvalidStateTransition`] if not currently `Running`.
    pub fn complete(&mut self) -> Result<(), DomainError> {
        if self.status != ScanStatus::Running {
            return Err(DomainError::InvalidStateTransition {
                from: format!("{:?}", self.status),
                to: "Completed".to_string(),
            });
        }
        self.status = ScanStatus::Completed;
        self.completed_at = Some(Utc::now());
        Ok(())
    }

    /// Transitions scan state to `Failed`.
    pub fn fail(&mut self) {
        self.status = ScanStatus::Failed;
        self.completed_at = Some(Utc::now());
    }

    /// Transitions scan state to `Cancelled`.
    ///
    /// # Errors
    /// Returns [`DomainError::InvalidStateTransition`] if already in a terminal state.
    pub fn cancel(&mut self) -> Result<(), DomainError> {
        if self.status.is_terminal() {
            return Err(DomainError::InvalidStateTransition {
                from: format!("{:?}", self.status),
                to: "Cancelled".to_string(),
            });
        }
        self.status = ScanStatus::Cancelled;
        self.completed_at = Some(Utc::now());
        Ok(())
    }
}

/// Lifecycle status of an individual queued scan job.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Default, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum JobStatus {
    /// Queued in the database waiting for a worker to claim it.
    #[default]
    Queued,
    /// Currently being processed by a worker or agent.
    Running,
    /// Execution finished successfully.
    Completed,
    /// Execution failed after exhaustion of retry attempts.
    Failed,
}

/// An atomic unit of work targeting a single asset.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ScanJob {
    /// Unique identifier for this job.
    pub id: ScanJobId,
    /// Parent scan execution session.
    pub scan_id: ScanId,
    /// Owning organization (tenant boundary).
    pub organization_id: OrganizationId,
    /// Target asset to be audited.
    pub asset_id: AssetId,
    /// Current execution state.
    pub status: JobStatus,
    /// Job priority (higher integer indicates higher priority).
    pub priority: i32,
    /// Number of execution attempts made.
    pub attempts: u32,
    /// Maximum allowable retry attempts before failing permanently.
    pub max_attempts: u32,
    /// Earliest timestamp at which this job is eligible to run.
    pub scheduled_at: DateTime<Utc>,
    /// Timestamp when a worker claimed and started this job.
    pub started_at: Option<DateTime<Utc>>,
    /// Timestamp when processing finished.
    pub completed_at: Option<DateTime<Utc>>,
    /// Error description if processing failed.
    pub error_message: Option<String>,
}

impl ScanJob {
    /// Default maximum attempts before a job is declared failed.
    pub const DEFAULT_MAX_ATTEMPTS: u32 = 3;

    /// Constructs a new queued [`ScanJob`].
    #[must_use]
    pub fn new(scan_id: ScanId, organization_id: OrganizationId, asset_id: AssetId) -> Self {
        Self {
            id: ScanJobId::new(),
            scan_id,
            organization_id,
            asset_id,
            status: JobStatus::Queued,
            priority: 0,
            attempts: 0,
            max_attempts: Self::DEFAULT_MAX_ATTEMPTS,
            scheduled_at: Utc::now(),
            started_at: None,
            completed_at: None,
            error_message: None,
        }
    }
}

impl fmt::Display for Scan {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "Scan({}, status={:?}, total_findings={})",
            self.id,
            self.status,
            self.summary.total()
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_scan_lifecycle_transitions() {
        let org_id = OrganizationId::new();
        let mut scan = Scan::new(org_id, TriggerType::Manual);
        assert_eq!(scan.status, ScanStatus::Pending);
        assert!(!scan.status.is_terminal());

        // Start
        scan.start().expect("pending to running is valid");
        assert_eq!(scan.status, ScanStatus::Running);
        assert!(scan.started_at.is_some());

        // Invalid start while running
        assert!(scan.start().is_err());

        // Complete
        scan.complete().expect("running to completed is valid");
        assert_eq!(scan.status, ScanStatus::Completed);
        assert!(scan.status.is_terminal());
        assert!(scan.completed_at.is_some());

        // Cannot cancel already completed scan
        assert!(scan.cancel().is_err());
    }

    #[test]
    fn test_scan_summary_aggregation() {
        let mut summary = ScanSummary::default();
        summary.record(Severity::Critical);
        summary.record(Severity::Critical);
        summary.record(Severity::High);
        summary.record(Severity::Low);

        assert_eq!(summary.critical, 2);
        assert_eq!(summary.high, 1);
        assert_eq!(summary.medium, 0);
        assert_eq!(summary.low, 1);
        assert_eq!(summary.info, 0);
        assert_eq!(summary.total(), 4);
    }

    #[test]
    fn test_scan_job_creation() {
        let scan_id = ScanId::new();
        let org_id = OrganizationId::new();
        let asset_id = AssetId::new();
        let job = ScanJob::new(scan_id, org_id, asset_id);

        assert_eq!(job.status, JobStatus::Queued);
        assert_eq!(job.attempts, 0);
        assert_eq!(job.max_attempts, 3);
        assert!(job.started_at.is_none());
    }

    #[test]
    fn test_assessment_type_invariants_and_serde() {
        let local = AssessmentType::LocalHostAssessment;
        assert_eq!(local.display_name(), "Local Host Assessment");
        assert!(local.provides_operating_system_audit());

        let remote_net = AssessmentType::RemoteNetworkAssessment;
        assert_eq!(remote_net.display_name(), "Remote Network Assessment");
        assert!(!remote_net.provides_operating_system_audit());

        let remote_auth = AssessmentType::AuthenticatedRemoteHostAssessment;
        assert_eq!(
            remote_auth.display_name(),
            "Authenticated Remote Host Assessment"
        );
        assert!(remote_auth.provides_operating_system_audit());

        let agent = AssessmentType::EnrolledAgentHostAssessment;
        assert_eq!(agent.display_name(), "Enrolled Agent Host Assessment");
        assert!(agent.provides_operating_system_audit());

        // Serde roundtrip
        let serialized = serde_json::to_string(&remote_net).expect("serialize");
        assert_eq!(serialized, "\"remote_network_assessment\"");
        let deserialized: AssessmentType = serde_json::from_str(&serialized).expect("deserialize");
        assert_eq!(deserialized, remote_net);
    }
}
