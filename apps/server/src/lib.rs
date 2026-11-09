//! # OpenAudit Server Library
//!
//! Control plane API, persistence layer, assessment orchestration, and task scheduler.

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
    clippy::too_many_arguments
)]

pub mod api;
pub mod auth;
pub mod config;
pub mod orchestration;
pub mod scheduler;
pub mod state;
pub mod store;

use std::sync::Arc;
use tokio::net::TcpListener;

use config::ServerConfig;
use orchestration::JobQueue;
use scheduler::ScheduleRunner;
use state::AppState;
use store::ControlPlaneStore;

/// Initializes and runs the control plane HTTP server with graceful shutdown handling.
///
/// # Errors
///
/// Returns an error if socket binding or listener execution encounters an I/O failure.
pub async fn run_server(
    config: ServerConfig,
    store: Arc<dyn ControlPlaneStore>,
) -> Result<(), Box<dyn std::error::Error>> {
    let bind_addr = config.bind_addr;
    let queue = JobQueue::new(config.max_concurrent_jobs);

    // Recover any jobs interrupted by a previous server restart
    if let Ok(count) = store.recover_interrupted_jobs().await {
        if count > 0 {
            tracing::warn!("Recovered {count} interrupted jobs from previous server execution");
        }
    }

    // Start background schedule evaluator
    let scheduler = ScheduleRunner::new(store.clone(), queue.clone());
    scheduler.start();

    let state = Arc::new(AppState::new(config, store, queue));
    let app = api::create_router(state);

    tracing::info!("OpenAudit control plane binding on http://{bind_addr}");
    let listener = TcpListener::bind(bind_addr).await?;
    tracing::info!("OpenAudit control plane listening on http://{bind_addr}");

    axum::serve(listener, app)
        .with_graceful_shutdown(shutdown_signal())
        .await?;

    tracing::info!("OpenAudit control plane server cleanly terminated");
    Ok(())
}

/// Awaits SIGINT (`Ctrl+C`) or SIGTERM signal for graceful shutdown.
async fn shutdown_signal() {
    let ctrl_c = async {
        let _ = tokio::signal::ctrl_c().await;
    };

    #[cfg(unix)]
    let terminate = async {
        if let Ok(mut sig) =
            tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())
        {
            sig.recv().await;
        } else {
            std::future::pending::<()>().await;
        }
    };

    #[cfg(not(unix))]
    let terminate = std::future::pending::<()>();

    tokio::select! {
        () = ctrl_c => {
            tracing::info!("Received SIGINT shutdown signal");
        },
        () = terminate => {
            tracing::info!("Received SIGTERM shutdown signal");
        },
    }
}
