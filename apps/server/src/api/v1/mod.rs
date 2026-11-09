//! API Version 1 routes.

pub mod agents;
pub mod assessments;
pub mod assets;
pub mod auth;
pub mod orgs;
pub mod schedules;

use axum::routing::{delete, get, post};
use axum::Router;
use std::sync::Arc;

use crate::state::AppState;

/// Assembles the complete `/api/v1` router.
pub fn router() -> Router<Arc<AppState>> {
    Router::new()
        // Auth
        .route("/auth/login", post(auth::login_handler))
        .route("/auth/bootstrap", post(auth::bootstrap_handler))
        .route("/auth/logout", post(auth::logout_handler))
        .route("/auth/me", get(auth::me_handler))
        // Organizations & Users
        .route("/organizations/current", get(orgs::get_current_org_handler))
        .route("/organizations/users", get(orgs::list_org_users_handler))
        .route("/organizations/users", post(orgs::create_org_user_handler))
        // Assets
        .route("/assets", post(assets::create_asset_handler))
        .route("/assets", get(assets::list_assets_handler))
        .route("/assets/:id", get(assets::get_asset_handler))
        .route("/assets/:id", delete(assets::delete_asset_handler))
        // Assessments
        .route("/assessments/jobs", post(assessments::create_job_handler))
        .route("/assessments/jobs", get(assessments::list_jobs_handler))
        .route("/assessments/jobs/:id", get(assessments::get_job_handler))
        .route(
            "/assessments/jobs/:id/cancel",
            post(assessments::cancel_job_handler),
        )
        .route(
            "/assessments/jobs/:id/findings",
            get(assessments::get_job_findings_handler),
        )
        .route(
            "/assessments/findings",
            get(assessments::list_all_findings_handler),
        )
        // Schedules
        .route("/schedules", post(schedules::create_schedule_handler))
        .route("/schedules", get(schedules::list_schedules_handler))
        // Operator Agent Management (Tenant-Scoped)
        .route(
            "/agents/tokens",
            post(agents::create_enrollment_token_handler),
        )
        .route("/agents", get(agents::list_agents_handler))
        .route("/agents/:id", get(agents::get_agent_handler))
        .route("/agents/:id/revoke", post(agents::revoke_agent_handler))
        // Outbound Agent Communication
        .route("/agent/enroll", post(agents::agent_enroll_handler))
        .route("/agent/heartbeat", post(agents::agent_heartbeat_handler))
        .route("/agent/jobs/poll", post(agents::agent_poll_jobs_handler))
        .route(
            "/agent/jobs/:id/heartbeat",
            post(agents::agent_job_heartbeat_handler),
        )
        .route(
            "/agent/jobs/:id/results",
            post(agents::agent_submit_results_handler),
        )
        .route("/agent/jobs/:id/fail", post(agents::agent_fail_job_handler))
        .route(
            "/agent/rotate-credentials",
            post(agents::agent_rotate_credentials_handler),
        )
}
