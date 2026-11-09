//! Assessment executor invoking the shared AuditEngine and PerimeterAssessor.

use chrono::Utc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;

use crate::store::models::{AssessmentJob, NewFinding};
use crate::store::ControlPlaneStore;
use openaudit_core::OrganizationId;
use openaudit_engine::{AuditEngine, AuditProfile};
use openaudit_network::{
    PerimeterAssessConfig, PerimeterAssessor, PerimeterProfile, SystemDnsResolver, TargetScope,
};

/// Result summary of an executed assessment job.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct JobExecutionSummary {
    pub findings_count: usize,
    pub duration_ms: u64,
    pub assessment_type: String,
    pub completed_at: String,
}

/// Executes an assessment job and records discovered findings into the store.
///
/// # Errors
///
/// Returns an error string if assessment fails or is cancelled.
pub async fn execute_assessment(
    job: &AssessmentJob,
    store: &Arc<dyn ControlPlaneStore>,
    cancel_token: Arc<AtomicBool>,
) -> Result<JobExecutionSummary, String> {
    let start_time = std::time::Instant::now();

    if cancel_token.load(Ordering::Relaxed) {
        return Err("Assessment job was cancelled before execution".to_string());
    }

    match job.assessment_type.as_str() {
        "local_host" => {
            let profile = match job.profile.to_lowercase().as_str() {
                "hardened" => AuditProfile::Hardened,
                "full" => AuditProfile::Full,
                _ => AuditProfile::Baseline,
            };

            let org_id = OrganizationId::from_seed(job.org_id.as_bytes());
            let engine = AuditEngine::default();

            // Run CPU-bound / OS-bound audit on a blocking thread
            let report =
                tokio::task::spawn_blocking(move || engine.run_audit_with_profile(org_id, profile))
                    .await
                    .map_err(|e| format!("Join error: {e}"))?
                    .map_err(|e| format!("Audit engine failed: {e}"))?;

            if cancel_token.load(Ordering::Relaxed) {
                return Err("Assessment job was cancelled during execution".to_string());
            }

            let new_findings: Vec<NewFinding> = report
                .findings
                .into_iter()
                .map(|item| NewFinding {
                    rule_id: item.finding.rule_id,
                    severity: format!("{:?}", item.finding.severity),
                    confidence: "Confirmed".to_string(),
                    title: item.finding.title,
                    endpoint: item.target,
                    evidence: item.evidence.payload.data().to_string(),
                    recommendation: item.finding.remediation,
                })
                .collect();

            let findings_count = new_findings.len();
            if !new_findings.is_empty() {
                store
                    .create_findings(job.org_id, job.id, &new_findings)
                    .await
                    .map_err(|e| format!("Failed to store findings: {e}"))?;
            }

            let duration_ms = start_time.elapsed().as_millis() as u64;
            Ok(JobExecutionSummary {
                findings_count,
                duration_ms,
                assessment_type: "local_host".into(),
                completed_at: Utc::now().to_rfc3339(),
            })
        }
        "remote_network" | "perimeter" => {
            let profile = match job.profile.to_lowercase().as_str() {
                "conservative" => PerimeterProfile::Conservative,
                "deep" => PerimeterProfile::Deep,
                _ => PerimeterProfile::Standard,
            };
            let ports = profile.default_ports();

            // Default scope for remote network assessment
            let scope = TargetScope {
                allow_public: true,
                authorized_cidrs: Vec::new(),
                allow_loopback: false,
                allow_link_local: false,
                allow_testnets: true,
                explicit_allowed_ips: std::collections::HashSet::new(),
            };

            let target = job.target.clone();
            let config = PerimeterAssessConfig::default();
            let cancel_clone = cancel_token.clone();

            let report = tokio::task::spawn_blocking(move || {
                let resolver = SystemDnsResolver;
                PerimeterAssessor::assess(
                    &target,
                    &ports,
                    &scope,
                    &resolver,
                    &config,
                    Some(cancel_clone),
                )
            })
            .await
            .map_err(|e| format!("Join error: {e}"))?
            .map_err(|e| format!("Perimeter assessor failed: {e}"))?;

            if cancel_token.load(Ordering::Relaxed) {
                return Err("Assessment job was cancelled".to_string());
            }

            let new_findings: Vec<NewFinding> = report
                .findings
                .into_iter()
                .map(|f| NewFinding {
                    rule_id: f.id,
                    severity: format!("{:?}", f.severity),
                    confidence: f.confidence,
                    title: f.title,
                    endpoint: f.endpoint,
                    evidence: f.evidence,
                    recommendation: f.recommendation,
                })
                .collect();

            let findings_count = new_findings.len();
            if !new_findings.is_empty() {
                store
                    .create_findings(job.org_id, job.id, &new_findings)
                    .await
                    .map_err(|e| format!("Failed to store findings: {e}"))?;
            }

            let duration_ms = start_time.elapsed().as_millis() as u64;
            Ok(JobExecutionSummary {
                findings_count,
                duration_ms,
                assessment_type: "remote_network".into(),
                completed_at: Utc::now().to_rfc3339(),
            })
        }
        other => Err(format!(
            "Unsupported assessment type '{other}'. Expected: local_host, remote_network"
        )),
    }
}
