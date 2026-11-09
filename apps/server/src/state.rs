//! Shared application state for control-plane HTTP request handlers.

use std::sync::Arc;
use std::time::Instant;

use crate::config::ServerConfig;
use crate::orchestration::JobQueue;
use crate::store::ControlPlaneStore;

/// Global application state shared across all HTTP routes.
pub struct AppState {
    pub config: ServerConfig,
    pub store: Arc<dyn ControlPlaneStore>,
    pub queue: JobQueue,
    pub login_limiter: Arc<crate::auth::LoginRateLimiter>,
    started_at: Instant,
}

impl std::fmt::Debug for AppState {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("AppState")
            .field("config", &self.config)
            .field("queue", &self.queue)
            .finish_non_exhaustive()
    }
}

impl AppState {
    /// Creates a new `AppState` instance.
    #[must_use]
    pub fn new(config: ServerConfig, store: Arc<dyn ControlPlaneStore>, queue: JobQueue) -> Self {
        Self {
            config,
            store,
            queue,
            login_limiter: Arc::new(crate::auth::LoginRateLimiter::default()),
            started_at: Instant::now(),
        }
    }

    /// Returns the uptime in seconds since server initialization.
    #[must_use]
    pub fn uptime_secs(&self) -> u64 {
        self.started_at.elapsed().as_secs()
    }

    /// Returns the number of active assessment workers.
    #[must_use]
    pub fn active_worker_count(&self) -> usize {
        self.queue.active_worker_count()
    }
}
