//! Bounded concurrency assessment job queue and worker management.

use std::collections::HashMap;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use tokio::sync::Semaphore;
use uuid::Uuid;

use super::executor::execute_assessment;
use crate::store::models::{AssessmentJob, JobStatus};
use crate::store::ControlPlaneStore;

/// Bounded assessment queue managing asynchronous job execution.
#[derive(Clone)]
pub struct JobQueue {
    active_jobs: Arc<Mutex<HashMap<Uuid, Arc<AtomicBool>>>>,
    semaphore: Arc<Semaphore>,
    max_concurrency: usize,
}

impl std::fmt::Debug for JobQueue {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("JobQueue")
            .field("max_concurrency", &self.max_concurrency)
            .finish_non_exhaustive()
    }
}

impl JobQueue {
    /// Initializes a new bounded job queue.
    #[must_use]
    pub fn new(max_concurrency: usize) -> Self {
        let max = max_concurrency.clamp(1, 100);
        Self {
            active_jobs: Arc::new(Mutex::new(HashMap::new())),
            semaphore: Arc::new(Semaphore::new(max)),
            max_concurrency: max,
        }
    }

    /// Returns the number of currently active worker tasks.
    #[must_use]
    pub fn active_worker_count(&self) -> usize {
        self.max_concurrency
            .saturating_sub(self.semaphore.available_permits())
    }

    /// Submits a newly created assessment job for asynchronous execution.
    pub fn submit_job(&self, job: AssessmentJob, store: Arc<dyn ControlPlaneStore>) {
        let cancel_token = Arc::new(AtomicBool::new(false));
        {
            if let Ok(mut map) = self.active_jobs.lock() {
                map.insert(job.id, cancel_token.clone());
            }
        }

        let semaphore = self.semaphore.clone();
        let active_map = self.active_jobs.clone();

        tokio::spawn(async move {
            let Ok(_permit) = semaphore.acquire().await else {
                return; // Semaphore closed
            };

            // Transition to Running
            if let Err(err) = store
                .update_job_status(job.org_id, job.id, JobStatus::Running, None, None)
                .await
            {
                tracing::error!("Failed to update job {} to Running: {err}", job.id);
                if let Ok(mut map) = active_map.lock() {
                    map.remove(&job.id);
                }
                return;
            }

            // Execute the assessment
            let result = execute_assessment(&job, &store, cancel_token.clone()).await;

            // Transition to Completed or Failed
            match result {
                Ok(summary) => {
                    let summary_json = serde_json::to_string(&summary).ok();
                    let _ = store
                        .update_job_status(
                            job.org_id,
                            job.id,
                            JobStatus::Completed,
                            summary_json.as_deref(),
                            None,
                        )
                        .await;
                }
                Err(err) => {
                    let status = if cancel_token.load(Ordering::Relaxed) {
                        JobStatus::Cancelled
                    } else {
                        JobStatus::Failed
                    };
                    let _ = store
                        .update_job_status(job.org_id, job.id, status, None, Some(&err))
                        .await;
                }
            }

            if let Ok(mut map) = active_map.lock() {
                map.remove(&job.id);
            }
        });
    }

    /// Cancels a running or pending assessment job.
    pub fn cancel_job(&self, job_id: Uuid) -> bool {
        if let Ok(map) = self.active_jobs.lock() {
            if let Some(token) = map.get(&job_id) {
                token.store(true, Ordering::Relaxed);
                return true;
            }
        }
        false
    }
}
