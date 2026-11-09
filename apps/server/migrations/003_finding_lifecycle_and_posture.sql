-- OpenAudit Control Plane - PostgreSQL Schema Migration 003
-- Stable Finding Identity, Finding Lifecycle, Remediation Tracking, and Security Posture Intelligence

-- Alter assessment_jobs to record rules evaluated and engine version
ALTER TABLE assessment_jobs ADD COLUMN IF NOT EXISTS rules_evaluated TEXT;
ALTER TABLE assessment_jobs ADD COLUMN IF NOT EXISTS engine_version VARCHAR(64) NOT NULL DEFAULT '0.1.0-alpha.0';

-- Alter assessment_findings to record fingerprint and link to managed finding
ALTER TABLE assessment_findings ADD COLUMN IF NOT EXISTS fingerprint VARCHAR(64);
ALTER TABLE assessment_findings ADD COLUMN IF NOT EXISTS managed_finding_id UUID;

-- Durable Managed Findings table tracking issues across repeated assessments
CREATE TABLE IF NOT EXISTS managed_findings (
    id UUID PRIMARY KEY,
    org_id UUID NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
    asset_id UUID REFERENCES assets(id) ON DELETE CASCADE,
    fingerprint VARCHAR(64) NOT NULL,
    rule_id VARCHAR(128) NOT NULL,
    domain VARCHAR(64) NOT NULL,
    endpoint VARCHAR(255) NOT NULL,
    title VARCHAR(255) NOT NULL,
    severity VARCHAR(32) NOT NULL,
    confidence VARCHAR(32) NOT NULL,
    status VARCHAR(32) NOT NULL DEFAULT 'open',
    resolution_type VARCHAR(32),
    first_observed_at TIMESTAMPTZ NOT NULL,
    last_observed_at TIMESTAMPTZ NOT NULL,
    first_job_id UUID NOT NULL REFERENCES assessment_jobs(id) ON DELETE CASCADE,
    last_job_id UUID NOT NULL REFERENCES assessment_jobs(id) ON DELETE CASCADE,
    occurrence_count INTEGER NOT NULL DEFAULT 1,
    assigned_owner VARCHAR(255),
    due_date TIMESTAMPTZ,
    remediation_notes TEXT,
    created_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
    CONSTRAINT uq_managed_findings_org_fp UNIQUE(org_id, fingerprint)
);

-- Add foreign key constraint for assessment_findings.managed_finding_id if not present
DO $$
BEGIN
    IF NOT EXISTS (
        SELECT 1 FROM pg_constraint WHERE conname = 'fk_findings_managed_finding'
    ) THEN
        ALTER TABLE assessment_findings
        ADD CONSTRAINT fk_findings_managed_finding
        FOREIGN KEY (managed_finding_id) REFERENCES managed_findings(id) ON DELETE SET NULL;
    END IF;
END $$;

-- Finding status transition audit history
CREATE TABLE IF NOT EXISTS finding_status_history (
    id UUID PRIMARY KEY,
    finding_id UUID NOT NULL REFERENCES managed_findings(id) ON DELETE CASCADE,
    old_status VARCHAR(32) NOT NULL,
    new_status VARCHAR(32) NOT NULL,
    resolution_type VARCHAR(32),
    changed_by_user_id UUID REFERENCES users(id) ON DELETE SET NULL,
    job_id UUID REFERENCES assessment_jobs(id) ON DELETE SET NULL,
    comment TEXT,
    created_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP
);

-- Indexes for performance and isolation
CREATE INDEX IF NOT EXISTS idx_managed_findings_org_status ON managed_findings(org_id, status);
CREATE INDEX IF NOT EXISTS idx_managed_findings_org_asset ON managed_findings(org_id, asset_id);
CREATE INDEX IF NOT EXISTS idx_managed_findings_org_severity ON managed_findings(org_id, severity);
CREATE INDEX IF NOT EXISTS idx_finding_history_finding ON finding_status_history(finding_id, created_at);
CREATE INDEX IF NOT EXISTS idx_assessment_findings_fp ON assessment_findings(fingerprint);
