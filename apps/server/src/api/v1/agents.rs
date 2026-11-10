//! Agent enrollment, management, and outbound communication endpoints (M6).

use argon2::password_hash::rand_core::{OsRng, RngCore};
use axum::extract::{Path as AxumPath, State};
use axum::http::{HeaderMap, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::Json;
use chrono::Utc;
use serde::{Deserialize, Serialize};
use serde_json::json;
use sha2::{Digest, Sha256};
use std::sync::Arc;
use uuid::Uuid;

use crate::auth::AuthenticatedUser;
use crate::state::AppState;
use crate::store::models::{AgentStatus, EnrolledAgent, NewFinding, Role};
use crate::store::StoreError;

fn encode_hex(bytes: &[u8]) -> String {
    use std::fmt::Write;
    let mut s = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        let _ = write!(s, "{b:02x}");
    }
    s
}

fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    let mut res = 0u8;
    for (&x, &y) in a.iter().zip(b.iter()) {
        res |= x ^ y;
    }
    res == 0
}

/// Hashes an agent authentication key or enrollment secret using SHA-256.
#[must_use]
pub fn hash_agent_key(key: &str) -> String {
    let mut hasher = Sha256::new();
    hasher.update(key.as_bytes());
    encode_hex(&hasher.finalize())
}

/// Generates a high-entropy cryptographically secure random hex token (64 hex characters / 32 bytes = 256 bits of entropy).
#[must_use]
pub fn generate_random_token() -> String {
    let mut bytes = [0u8; 32];
    OsRng.fill_bytes(&mut bytes);
    encode_hex(&bytes)
}

// =========================================================================
// Operator APIs (Tenant-Scoped)
// =========================================================================

#[derive(Debug, Deserialize)]
pub struct CreateEnrollmentTokenRequest {
    pub machine_id: Option<String>,
    pub ttl_minutes: Option<u32>,
}

#[derive(Debug, Serialize)]
pub struct CreateEnrollmentTokenResponse {
    pub token_id: Uuid,
    pub token_secret: String,
    pub challenge_nonce: String,
    pub expires_at: chrono::DateTime<Utc>,
    pub machine_id: Option<String>,
}

/// Handler for `POST /api/v1/agents/tokens` (Operator generates enrollment token).
pub async fn create_enrollment_token_handler(
    State(state): State<Arc<AppState>>,
    auth: AuthenticatedUser,
    Json(payload): Json<CreateEnrollmentTokenRequest>,
) -> Response {
    if !auth.role.can_manage_assets() {
        return (
            StatusCode::FORBIDDEN,
            Json(json!({
                "error": "forbidden",
                "message": "Only admins and auditors can issue agent enrollment tokens"
            })),
        )
            .into_response();
    }

    let token_secret = generate_random_token();
    let token_secret_hash = hash_agent_key(&token_secret);
    let challenge_nonce = generate_random_token();
    let ttl_mins = payload.ttl_minutes.unwrap_or(30).clamp(1, 1440); // 1 min to 24 hrs
    let expires_at = Utc::now() + chrono::Duration::minutes(i64::from(ttl_mins));

    let clean_machine = payload
        .machine_id
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty());

    match state
        .store
        .issue_agent_enrollment_token(
            auth.org_id,
            &token_secret_hash,
            clean_machine.as_deref(),
            &challenge_nonce,
            expires_at,
        )
        .await
    {
        Ok(tok) => (
            StatusCode::CREATED,
            Json(CreateEnrollmentTokenResponse {
                token_id: tok.id,
                token_secret,
                challenge_nonce,
                expires_at,
                machine_id: clean_machine,
            }),
        )
            .into_response(),
        Err(err) => (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(json!({ "error": "database_error", "message": err.to_string() })),
        )
            .into_response(),
    }
}

/// Handler for `GET /api/v1/agents` (Operator lists tenant agents).
pub async fn list_agents_handler(
    State(state): State<Arc<AppState>>,
    auth: AuthenticatedUser,
) -> Response {
    match state.store.list_agents(auth.org_id).await {
        Ok(agents) => (StatusCode::OK, Json(json!({ "agents": agents }))).into_response(),
        Err(err) => (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(json!({ "error": "database_error", "message": err.to_string() })),
        )
            .into_response(),
    }
}

/// Handler for `GET /api/v1/agents/:id` (Operator inspects agent).
pub async fn get_agent_handler(
    State(state): State<Arc<AppState>>,
    auth: AuthenticatedUser,
    AxumPath(agent_id): AxumPath<Uuid>,
) -> Response {
    match state.store.get_agent_by_id(auth.org_id, agent_id).await {
        Ok(Some(agent)) => (StatusCode::OK, Json(agent)).into_response(),
        Ok(None) => (
            StatusCode::NOT_FOUND,
            Json(json!({ "error": "not_found", "message": "Agent not found" })),
        )
            .into_response(),
        Err(err) => (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(json!({ "error": "database_error", "message": err.to_string() })),
        )
            .into_response(),
    }
}

/// Handler for `POST /api/v1/agents/:id/revoke` (Operator revokes agent).
pub async fn revoke_agent_handler(
    State(state): State<Arc<AppState>>,
    auth: AuthenticatedUser,
    AxumPath(agent_id): AxumPath<Uuid>,
) -> Response {
    if auth.role != Role::Admin {
        return (
            StatusCode::FORBIDDEN,
            Json(json!({
                "error": "forbidden",
                "message": "Only administrators can revoke agent credentials"
            })),
        )
            .into_response();
    }

    match state
        .store
        .update_agent_status(auth.org_id, agent_id, AgentStatus::Revoked)
        .await
    {
        Ok(()) => (
            StatusCode::OK,
            Json(json!({
                "status": "revoked",
                "message": format!("Agent {agent_id} has been revoked")
            })),
        )
            .into_response(),
        Err(StoreError::NotFound(_)) => (
            StatusCode::NOT_FOUND,
            Json(json!({ "error": "not_found", "message": "Agent not found" })),
        )
            .into_response(),
        Err(err) => (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(json!({ "error": "database_error", "message": err.to_string() })),
        )
            .into_response(),
    }
}

// =========================================================================
// Agent Communication APIs (Outbound Only)
// =========================================================================

#[derive(Debug, Deserialize)]
pub struct AgentEnrollmentRequest {
    pub token_id: Uuid,
    pub token_secret: String,
    pub challenge_response: String,
    pub machine_id: String,
    pub hostname: String,
    pub agent_version: String,
    pub public_identity: String,
    pub capabilities: Option<Vec<String>>,
}

#[derive(Debug, Serialize)]
pub struct AgentEnrollmentResponse {
    pub agent_id: Uuid,
    pub org_id: Uuid,
    pub auth_key: String,
    pub heartbeat_interval_secs: u64,
    pub poll_interval_secs: u64,
}

/// Handler for `POST /api/v1/agent/enroll` (Outbound agent registration).
pub async fn agent_enroll_handler(
    State(state): State<Arc<AppState>>,
    Json(payload): Json<AgentEnrollmentRequest>,
) -> Response {
    // 1. Validate parameter lengths and bounds
    let machine_id = payload.machine_id.trim();
    let hostname = payload.hostname.trim();
    let agent_version = payload.agent_version.trim();
    let public_identity = payload.public_identity.trim();

    if machine_id.is_empty() || machine_id.len() > 64 {
        return (
            StatusCode::BAD_REQUEST,
            Json(json!({ "error": "invalid_machine_id", "message": "machine_id must be between 1 and 64 characters" })),
        ).into_response();
    }
    if hostname.is_empty() || hostname.len() > 255 {
        return (
            StatusCode::BAD_REQUEST,
            Json(json!({ "error": "invalid_hostname", "message": "hostname must be between 1 and 255 characters" })),
        ).into_response();
    }
    if agent_version.is_empty() || agent_version.len() > 64 {
        return (
            StatusCode::BAD_REQUEST,
            Json(json!({ "error": "invalid_agent_version", "message": "agent_version must be between 1 and 64 characters" })),
        ).into_response();
    }

    // 2. Fetch enrollment token
    let token = match state
        .store
        .get_agent_enrollment_token(payload.token_id)
        .await
    {
        Ok(Some(t)) => t,
        Ok(None) => {
            return (
                StatusCode::UNAUTHORIZED,
                Json(json!({ "error": "invalid_token", "message": "Enrollment token not found" })),
            )
                .into_response();
        }
        Err(err) => {
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(json!({ "error": "database_error", "message": err.to_string() })),
            )
                .into_response();
        }
    };

    // Check expiration
    if token.expires_at < Utc::now() {
        return (
            StatusCode::UNAUTHORIZED,
            Json(json!({ "error": "token_expired", "message": "Enrollment token has expired" })),
        )
            .into_response();
    }

    // Check if already used
    if token.used_at.is_some() {
        return (
            StatusCode::CONFLICT,
            Json(json!({ "error": "token_already_used", "message": "Enrollment token has already been consumed" })),
        )
            .into_response();
    }

    // Constant-time verify secret against stored SHA-256 hash
    let presented_secret_hash = hash_agent_key(&payload.token_secret);
    if !constant_time_eq(
        presented_secret_hash.as_bytes(),
        token.token_secret.as_bytes(),
    ) {
        return (
            StatusCode::UNAUTHORIZED,
            Json(json!({ "error": "invalid_token_secret", "message": "Invalid token secret" })),
        )
            .into_response();
    }

    // Verify machine_id binding if token specified an expected machine_id
    if let Some(expected_machine) = &token.machine_id {
        if expected_machine != machine_id {
            return (
                StatusCode::FORBIDDEN,
                Json(json!({
                    "error": "machine_id_mismatch",
                    "message": "Enrollment token is restricted to a different machine_id"
                })),
            )
                .into_response();
        }
    }

    // Challenge response verification (constant-time verification of challenge nonce and machine_id)
    let expected_challenge = format!("{}:{}", token.challenge_nonce, machine_id);
    if !constant_time_eq(
        payload.challenge_response.trim().as_bytes(),
        expected_challenge.as_bytes(),
    ) {
        return (
            StatusCode::UNAUTHORIZED,
            Json(json!({ "error": "invalid_challenge_response", "message": "Challenge response verification failed" })),
        )
            .into_response();
    }

    // 3. Atomically consume token
    if let Err(err) = state.store.consume_enrollment_token(token.id).await {
        return (
            StatusCode::CONFLICT,
            Json(json!({ "error": "token_consumption_failed", "message": err.to_string() })),
        )
            .into_response();
    }

    // 4. Generate persistent Agent Auth Key
    let auth_key = generate_random_token();
    let auth_key_hash = hash_agent_key(&auth_key);

    let caps = payload
        .capabilities
        .unwrap_or_else(|| vec!["host_audit".to_string(), "perimeter_scan".to_string()]);
    let caps_json = serde_json::to_string(&caps).unwrap_or_else(|_| "[]".to_string());

    // 5. Enroll agent in persistent store
    match state
        .store
        .enroll_agent(
            token.org_id,
            machine_id,
            hostname,
            agent_version,
            &auth_key_hash,
            public_identity,
            &caps_json,
        )
        .await
    {
        Ok(agent) => (
            StatusCode::CREATED,
            Json(AgentEnrollmentResponse {
                agent_id: agent.id,
                org_id: agent.org_id,
                auth_key,
                heartbeat_interval_secs: 15,
                poll_interval_secs: 5,
            }),
        )
            .into_response(),
        Err(err) => (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(json!({ "error": "enrollment_failed", "message": err.to_string() })),
        )
            .into_response(),
    }
}

/// Helper function to authenticate an outbound agent request from HTTP headers.
async fn authenticate_agent(
    state: &Arc<AppState>,
    headers: &HeaderMap,
) -> Result<EnrolledAgent, Response> {
    let raw_key = headers
        .get("Authorization")
        .and_then(|v| v.to_str().ok())
        .and_then(|h| h.strip_prefix("Bearer "))
        .or_else(|| headers.get("X-Agent-Key").and_then(|v| v.to_str().ok()));

    let Some(key) = raw_key else {
        return Err((
            StatusCode::UNAUTHORIZED,
            Json(json!({
                "error": "missing_credentials",
                "message": "Authorization header or X-Agent-Key required"
            })),
        )
            .into_response());
    };

    let key_hash = hash_agent_key(key);
    let agent_opt = state
        .store
        .get_agent_by_auth_hash(&key_hash)
        .await
        .map_err(|err| {
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(json!({ "error": "database_error", "message": err.to_string() })),
            )
                .into_response()
        })?;

    let Some(agent) = agent_opt else {
        return Err((
            StatusCode::UNAUTHORIZED,
            Json(json!({
                "error": "invalid_credentials",
                "message": "Unrecognized or invalid agent credentials"
            })),
        )
            .into_response());
    };

    if agent.status != AgentStatus::Active {
        let err_code = match agent.status {
            AgentStatus::Revoked => "agent_revoked",
            AgentStatus::Pending => "agent_pending_approval",
            AgentStatus::Active => "agent_inactive",
        };
        return Err((
            StatusCode::FORBIDDEN,
            Json(json!({
                "error": err_code,
                "message": format!("Agent is not active (status: {:?})", agent.status)
            })),
        )
            .into_response());
    }

    Ok(agent)
}

/// Handler for `POST /api/v1/agent/heartbeat`.
pub async fn agent_heartbeat_handler(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
) -> Response {
    let agent = match authenticate_agent(&state, &headers).await {
        Ok(a) => a,
        Err(resp) => return resp,
    };

    let now = Utc::now();
    let _ = state.store.update_agent_heartbeat(agent.id, now).await;

    (
        StatusCode::OK,
        Json(json!({
            "status": "active",
            "server_time": now,
            "poll_interval_secs": 5
        })),
    )
        .into_response()
}

/// Handler for `POST /api/v1/agent/jobs/poll`.
pub async fn agent_poll_jobs_handler(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
) -> Response {
    let agent = match authenticate_agent(&state, &headers).await {
        Ok(a) => a,
        Err(resp) => return resp,
    };

    let _ = state
        .store
        .update_agent_heartbeat(agent.id, Utc::now())
        .await;

    // Lease duration: 300 seconds (5 minutes)
    match state
        .store
        .claim_next_pending_job(agent.id, agent.org_id, 300)
        .await
    {
        Ok(Some(job)) => (
            StatusCode::OK,
            Json(json!({
                "job": {
                    "id": job.id,
                    "target": job.target,
                    "assessment_type": job.assessment_type,
                    "profile": job.profile,
                    "rules_subset": job.rules_subset,
                    "lease_expires_at": job.lease_expires_at
                }
            })),
        )
            .into_response(),
        Ok(None) => (StatusCode::OK, Json(json!({ "job": null }))).into_response(),
        Err(err) => (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(json!({ "error": "database_error", "message": err.to_string() })),
        )
            .into_response(),
    }
}

/// Handler for `POST /api/v1/agent/jobs/:id/heartbeat` (renews job lease).
pub async fn agent_job_heartbeat_handler(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    AxumPath(job_id): AxumPath<Uuid>,
) -> Response {
    let agent = match authenticate_agent(&state, &headers).await {
        Ok(a) => a,
        Err(resp) => return resp,
    };

    match state.store.renew_job_lease(agent.id, job_id, 300).await {
        Ok(true) => (
            StatusCode::OK,
            Json(json!({ "status": "renewed", "job_id": job_id })),
        )
            .into_response(),
        Ok(false) => (
            StatusCode::CONFLICT,
            Json(json!({
                "error": "lease_expired_or_not_assigned",
                "message": "Job lease cannot be renewed (job not running or assigned to different agent)"
            })),
        )
            .into_response(),
        Err(err) => (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(json!({ "error": "database_error", "message": err.to_string() })),
        )
            .into_response(),
    }
}

#[derive(Debug, Deserialize)]
pub struct SubmitJobResultsRequest {
    pub summary_json: Option<String>,
    pub findings: Vec<NewFindingPayload>,
}

#[derive(Debug, Deserialize)]
pub struct NewFindingPayload {
    pub rule_id: String,
    pub severity: String,
    pub confidence: String,
    pub title: String,
    pub endpoint: String,
    pub evidence: String,
    pub recommendation: String,
}

/// Handler for `POST /api/v1/agent/jobs/:id/results` (submits assessment results).
pub async fn agent_submit_results_handler(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    AxumPath(job_id): AxumPath<Uuid>,
    Json(payload): Json<SubmitJobResultsRequest>,
) -> Response {
    let agent = match authenticate_agent(&state, &headers).await {
        Ok(a) => a,
        Err(resp) => return resp,
    };

    let findings: Vec<NewFinding> = payload
        .findings
        .into_iter()
        .map(|f| NewFinding {
            rule_id: f.rule_id,
            severity: f.severity,
            confidence: f.confidence,
            title: f.title,
            endpoint: f.endpoint,
            // Prepend agent provenance metadata to evidence
            evidence: format!(
                "[Agent: {} ({})] {}",
                agent.hostname, agent.machine_id, f.evidence
            ),
            recommendation: f.recommendation,
        })
        .collect();

    match state
        .store
        .complete_agent_job(
            agent.id,
            job_id,
            agent.org_id,
            payload.summary_json.as_deref(),
            &[],
        )
        .await
    {
        Ok(()) => {
            // Reconcile findings into managed_findings lifecycle
            let rules_evaluated: Vec<String> = payload
                .summary_json
                .as_deref()
                .and_then(|s| serde_json::from_str::<serde_json::Value>(s).ok())
                .and_then(|v| {
                    v.get("evaluated")
                        .or_else(|| v.get("rules_evaluated"))
                        .and_then(|arr| arr.as_array())
                        .map(|arr| {
                            arr.iter()
                                .filter_map(|x| x.as_str().map(String::from))
                                .collect()
                        })
                })
                .unwrap_or_else(|| findings.iter().map(|f| f.rule_id.clone()).collect());

            if let Err(err) = state
                .store
                .record_job_findings_and_reconcile_lifecycle(
                    agent.org_id,
                    job_id,
                    &findings,
                    &rules_evaluated,
                )
                .await
            {
                tracing::error!("Failed to reconcile finding lifecycle for job {job_id}: {err}");
            }

            (
                StatusCode::OK,
                Json(json!({
                    "status": "completed",
                    "job_id": job_id,
                    "findings_recorded": findings.len()
                })),
            )
                .into_response()
        }
        Err(StoreError::Unauthorized(msg)) => (
            StatusCode::FORBIDDEN,
            Json(json!({ "error": "unauthorized", "message": msg })),
        )
            .into_response(),
        Err(StoreError::Conflict(msg)) => (
            StatusCode::CONFLICT,
            Json(json!({ "error": "conflict", "message": msg })),
        )
            .into_response(),
        Err(StoreError::NotFound(msg)) => (
            StatusCode::NOT_FOUND,
            Json(json!({ "error": "not_found", "message": msg })),
        )
            .into_response(),
        Err(err) => (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(json!({ "error": "database_error", "message": err.to_string() })),
        )
            .into_response(),
    }
}

#[derive(Debug, Deserialize)]
pub struct FailJobRequest {
    pub error_message: String,
}

/// Handler for `POST /api/v1/agent/jobs/:id/fail` (reports execution failure).
pub async fn agent_fail_job_handler(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    AxumPath(job_id): AxumPath<Uuid>,
    Json(payload): Json<FailJobRequest>,
) -> Response {
    let agent = match authenticate_agent(&state, &headers).await {
        Ok(a) => a,
        Err(resp) => return resp,
    };

    match state
        .store
        .fail_agent_job(agent.id, job_id, agent.org_id, &payload.error_message)
        .await
    {
        Ok(()) => (
            StatusCode::OK,
            Json(json!({ "status": "failed", "job_id": job_id })),
        )
            .into_response(),
        Err(StoreError::Conflict(msg)) => (
            StatusCode::CONFLICT,
            Json(json!({ "error": "conflict", "message": msg })),
        )
            .into_response(),
        Err(err) => (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(json!({ "error": "database_error", "message": err.to_string() })),
        )
            .into_response(),
    }
}

/// Handler for `POST /api/v1/agent/rotate-credentials`.
pub async fn agent_rotate_credentials_handler(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
) -> Response {
    let agent = match authenticate_agent(&state, &headers).await {
        Ok(a) => a,
        Err(resp) => return resp,
    };

    let new_auth_key = generate_random_token();
    let new_auth_hash = hash_agent_key(&new_auth_key);

    match state
        .store
        .rotate_agent_credential(agent.id, &new_auth_hash)
        .await
    {
        Ok(()) => (
            StatusCode::OK,
            Json(json!({
                "status": "rotated",
                "new_auth_key": new_auth_key,
                "message": "Credential rotated successfully. Use new_auth_key for future requests."
            })),
        )
            .into_response(),
        Err(err) => (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(json!({ "error": "rotation_failed", "message": err.to_string() })),
        )
            .into_response(),
    }
}
