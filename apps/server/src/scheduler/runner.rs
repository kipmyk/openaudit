//! Background schedule evaluation runner.

use chrono::{DateTime, Duration, Utc};
use std::sync::Arc;
use tokio::time::{interval, Duration as TokioDuration};

use crate::orchestration::JobQueue;
use crate::store::ControlPlaneStore;

/// Background runner that queries due schedules and enqueues assessment jobs.
pub struct ScheduleRunner {
    store: Arc<dyn ControlPlaneStore>,
    queue: JobQueue,
}

impl std::fmt::Debug for ScheduleRunner {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ScheduleRunner").finish_non_exhaustive()
    }
}

impl ScheduleRunner {
    #[must_use]
    pub fn new(store: Arc<dyn ControlPlaneStore>, queue: JobQueue) -> Self {
        Self { store, queue }
    }

    /// Spawns the background scheduler evaluation loop.
    pub fn start(self) {
        tokio::spawn(async move {
            let mut ticker = interval(TokioDuration::from_secs(30));
            loop {
                ticker.tick().await;
                self.evaluate_due_schedules();
            }
        });
    }

    /// Evaluates currently due schedules and enqueues their jobs.
    pub fn evaluate_due_schedules(&self) {
        let due = match self.store.get_due_schedules() {
            Ok(s) => s,
            Err(err) => {
                tracing::warn!("Failed to query due schedules: {err}");
                return;
            }
        };

        let now = Utc::now();
        for schedule in due {
            tracing::info!(
                "Triggering scheduled assessment '{}' ({}) for target '{}'",
                schedule.name,
                schedule.id,
                schedule.target
            );

            // Create and submit job
            match self.store.create_job(
                schedule.org_id,
                schedule.asset_id,
                &schedule.target,
                &schedule.assessment_type,
                &schedule.profile,
            ) {
                Ok(job) => {
                    self.queue.submit_job(job, self.store.clone());

                    // Calculate next run time (default to 24 hours if simple daily schedule, or parse interval)
                    let next_run = calculate_next_run(&schedule.cron_expression, now);
                    let _ = self
                        .store
                        .update_schedule_run_state(schedule.id, now, Some(next_run));
                }
                Err(err) => {
                    tracing::error!("Failed to create job for schedule '{}': {err}", schedule.id);
                }
            }
        }
    }
}

/// Computes the next scheduled execution time from a cron expression or interval shorthand.
#[must_use]
pub fn calculate_next_run(cron: &str, from: DateTime<Utc>) -> DateTime<Utc> {
    match cron.trim().to_lowercase().as_str() {
        "@hourly" | "hourly" => from + Duration::hours(1),
        "@daily" | "daily" => from + Duration::days(1),
        "@weekly" | "weekly" => from + Duration::weeks(1),
        "@monthly" | "monthly" => from + Duration::days(30),
        _ => from + Duration::hours(24), // Conservative fallback
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_calculate_next_run_intervals() {
        let now = Utc::now();
        assert_eq!(calculate_next_run("@hourly", now), now + Duration::hours(1));
        assert_eq!(calculate_next_run("@daily", now), now + Duration::days(1));
        assert_eq!(calculate_next_run("@weekly", now), now + Duration::weeks(1));
    }
}
