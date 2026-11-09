-- OpenAudit Control Plane - PostgreSQL Schema Migration 001
-- Enforces tenant isolation, relational integrity, and indexing for enterprise fleets.

CREATE TABLE IF NOT EXISTS schema_migrations (
    version INTEGER PRIMARY KEY,
    applied_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS organizations (
    id UUID PRIMARY KEY,
    slug VARCHAR(64) UNIQUE NOT NULL,
    name VARCHAR(255) NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS users (
    id UUID PRIMARY KEY,
    org_id UUID NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
    email VARCHAR(255) NOT NULL,
    password_hash VARCHAR(255) NOT NULL,
    name VARCHAR(255) NOT NULL,
    role VARCHAR(32) NOT NULL DEFAULT 'viewer',
    is_active BOOLEAN NOT NULL DEFAULT TRUE,
    created_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
    CONSTRAINT uq_users_org_email UNIQUE(org_id, email)
);

CREATE TABLE IF NOT EXISTS assets (
    id UUID PRIMARY KEY,
    org_id UUID NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
    name VARCHAR(255) NOT NULL,
    asset_type VARCHAR(64) NOT NULL,
    target VARCHAR(255) NOT NULL,
    criticality VARCHAR(32) NOT NULL DEFAULT 'medium',
    created_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS assessment_jobs (
    id UUID PRIMARY KEY,
    org_id UUID NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
    asset_id UUID REFERENCES assets(id) ON DELETE SET NULL,
    target VARCHAR(255) NOT NULL,
    assessment_type VARCHAR(64) NOT NULL,
    profile VARCHAR(64) NOT NULL DEFAULT 'standard',
    status VARCHAR(32) NOT NULL DEFAULT 'pending',
    summary_json TEXT,
    error_message TEXT,
    started_at TIMESTAMPTZ,
    completed_at TIMESTAMPTZ,
    created_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS assessment_findings (
    id UUID PRIMARY KEY,
    org_id UUID NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
    job_id UUID NOT NULL REFERENCES assessment_jobs(id) ON DELETE CASCADE,
    rule_id VARCHAR(128) NOT NULL,
    severity VARCHAR(32) NOT NULL,
    confidence VARCHAR(32) NOT NULL,
    title VARCHAR(255) NOT NULL,
    endpoint VARCHAR(255) NOT NULL,
    evidence TEXT NOT NULL,
    remediation TEXT NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS assessment_schedules (
    id UUID PRIMARY KEY,
    org_id UUID NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
    asset_id UUID REFERENCES assets(id) ON DELETE SET NULL,
    name VARCHAR(255) NOT NULL,
    cron_expression VARCHAR(64) NOT NULL,
    target VARCHAR(255) NOT NULL,
    assessment_type VARCHAR(64) NOT NULL,
    profile VARCHAR(64) NOT NULL DEFAULT 'standard',
    is_active BOOLEAN NOT NULL DEFAULT TRUE,
    last_run_at TIMESTAMPTZ,
    next_run_at TIMESTAMPTZ,
    created_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP
);

-- Performance Indexes for Tenant Isolation & High Fleet Volume
CREATE INDEX IF NOT EXISTS idx_users_org ON users(org_id);
CREATE INDEX IF NOT EXISTS idx_users_email ON users(email);
CREATE INDEX IF NOT EXISTS idx_assets_org_target ON assets(org_id, target);
CREATE INDEX IF NOT EXISTS idx_jobs_org_status ON assessment_jobs(org_id, status);
CREATE INDEX IF NOT EXISTS idx_jobs_created_at ON assessment_jobs(created_at DESC);
CREATE INDEX IF NOT EXISTS idx_findings_org_job ON assessment_findings(org_id, job_id);
CREATE INDEX IF NOT EXISTS idx_findings_severity ON assessment_findings(org_id, severity);
CREATE INDEX IF NOT EXISTS idx_schedules_org ON assessment_schedules(org_id, is_active);
CREATE INDEX IF NOT EXISTS idx_schedules_due ON assessment_schedules(is_active, next_run_at) WHERE is_active = TRUE;

