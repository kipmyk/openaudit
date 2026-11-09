-- OpenAudit Control Plane - PostgreSQL Schema Migration 002
-- Agent Communication, Secure Enrollment, and Distributed Dispatch

CREATE TABLE IF NOT EXISTS agent_enrollment_tokens (
    id UUID PRIMARY KEY,
    org_id UUID NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
    token_secret VARCHAR(128) NOT NULL,
    machine_id VARCHAR(64),
    challenge_nonce VARCHAR(64) NOT NULL,
    expires_at TIMESTAMPTZ NOT NULL,
    used_at TIMESTAMPTZ,
    created_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS enrolled_agents (
    id UUID PRIMARY KEY,
    org_id UUID NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
    machine_id VARCHAR(64) NOT NULL,
    hostname VARCHAR(255) NOT NULL,
    agent_version VARCHAR(64) NOT NULL,
    status VARCHAR(32) NOT NULL DEFAULT 'active',
    auth_token_hash VARCHAR(255) NOT NULL,
    public_identity TEXT NOT NULL,
    capabilities TEXT NOT NULL DEFAULT '["host_audit","perimeter_scan"]',
    last_seen_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
    enrolled_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
    revoked_at TIMESTAMPTZ,
    created_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
    CONSTRAINT uq_agents_org_machine UNIQUE(org_id, machine_id)
);

ALTER TABLE assessment_jobs ADD COLUMN IF NOT EXISTS assigned_agent_id UUID REFERENCES enrolled_agents(id) ON DELETE SET NULL;
ALTER TABLE assessment_jobs ADD COLUMN IF NOT EXISTS lease_expires_at TIMESTAMPTZ;
ALTER TABLE assessment_jobs ADD COLUMN IF NOT EXISTS execution_source VARCHAR(32) NOT NULL DEFAULT 'server';
ALTER TABLE assessment_jobs ADD COLUMN IF NOT EXISTS rules_subset TEXT;

-- Indexes for Agent Lookups and Job Dispatch
CREATE INDEX IF NOT EXISTS idx_agent_tokens_lookup ON agent_enrollment_tokens(id, expires_at) WHERE used_at IS NULL;
CREATE INDEX IF NOT EXISTS idx_agents_org_status ON enrolled_agents(org_id, status);
CREATE INDEX IF NOT EXISTS idx_agents_auth_hash ON enrolled_agents(auth_token_hash);
CREATE INDEX IF NOT EXISTS idx_jobs_claimable ON assessment_jobs(status, lease_expires_at) WHERE status = 'pending' OR status = 'running';

