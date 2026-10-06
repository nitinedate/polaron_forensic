-- Per-firm schema template. {schema} is replaced at provision time.

CREATE TABLE IF NOT EXISTS "{schema}".users (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    email VARCHAR(255) NOT NULL UNIQUE,
    username VARCHAR(128),
    password_hash VARCHAR(255),
    status VARCHAR(32) NOT NULL DEFAULT 'pending',
    is_email_verified BOOLEAN NOT NULL DEFAULT FALSE,
    mfa_enabled BOOLEAN NOT NULL DEFAULT FALSE,
    profile JSONB,
    last_login_at TIMESTAMPTZ,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS "{schema}".permissions (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    code VARCHAR(128) NOT NULL UNIQUE,
    resource VARCHAR(64) NOT NULL,
    action VARCHAR(64) NOT NULL,
    description TEXT
);

CREATE TABLE IF NOT EXISTS "{schema}".roles (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    name VARCHAR(64) NOT NULL UNIQUE,
    description TEXT,
    is_system BOOLEAN NOT NULL DEFAULT FALSE
);

CREATE TABLE IF NOT EXISTS "{schema}".role_permissions (
    role_id UUID NOT NULL REFERENCES "{schema}".roles(id) ON DELETE CASCADE,
    permission_id UUID NOT NULL REFERENCES "{schema}".permissions(id) ON DELETE CASCADE,
    PRIMARY KEY (role_id, permission_id)
);

CREATE TABLE IF NOT EXISTS "{schema}".user_roles (
    user_id UUID NOT NULL REFERENCES "{schema}".users(id) ON DELETE CASCADE,
    role_id UUID NOT NULL REFERENCES "{schema}".roles(id) ON DELETE CASCADE,
    PRIMARY KEY (user_id, role_id)
);

CREATE TABLE IF NOT EXISTS "{schema}".invitations (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id UUID NOT NULL REFERENCES "{schema}".users(id) ON DELETE CASCADE,
    email VARCHAR(255) NOT NULL,
    token_hash VARCHAR(128) NOT NULL UNIQUE,
    token_plain VARCHAR(128),
    expires_at TIMESTAMPTZ NOT NULL,
    invited_by UUID,
    accepted_at TIMESTAMPTZ,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS "{schema}".mfa_totp (
    user_id UUID PRIMARY KEY REFERENCES "{schema}".users(id) ON DELETE CASCADE,
    secret VARCHAR(128) NOT NULL,
    confirmed BOOLEAN NOT NULL DEFAULT FALSE,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS "{schema}".mfa_recovery_codes (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id UUID NOT NULL REFERENCES "{schema}".users(id) ON DELETE CASCADE,
    code_hash VARCHAR(128) NOT NULL,
    used_at TIMESTAMPTZ
);

CREATE TABLE IF NOT EXISTS "{schema}".refresh_tokens (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id UUID NOT NULL REFERENCES "{schema}".users(id) ON DELETE CASCADE,
    token_hash VARCHAR(128) NOT NULL UNIQUE,
    expires_at TIMESTAMPTZ NOT NULL,
    revoked_at TIMESTAMPTZ,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS "{schema}".password_reset_tokens (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id UUID NOT NULL REFERENCES "{schema}".users(id) ON DELETE CASCADE,
    token_hash VARCHAR(128) NOT NULL UNIQUE,
    expires_at TIMESTAMPTZ NOT NULL,
    used_at TIMESTAMPTZ,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- Forensic case partitioning scaffold (Phase 2+)
CREATE TABLE IF NOT EXISTS "{schema}".forensic_cases (
    case_id UUID NOT NULL,
    id UUID NOT NULL DEFAULT gen_random_uuid(),
    title VARCHAR(512),
    status VARCHAR(32) NOT NULL DEFAULT 'open',
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    PRIMARY KEY (case_id, id)
) PARTITION BY LIST (case_id);

CREATE TABLE IF NOT EXISTS "{schema}".jobs (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    type VARCHAR(64) NOT NULL DEFAULT 'host_disk',
    status VARCHAR(32) NOT NULL DEFAULT 'created',
    domain_pack VARCHAR(64),
    case_id UUID,
    created_by UUID,
    progress_pct INTEGER NOT NULL DEFAULT 0,
    error TEXT,
    segment_readiness JSONB,
    disk_source JSONB,
    extracted_disk_uri TEXT,
    files_total INTEGER NOT NULL DEFAULT 0,
    files_extracted INTEGER NOT NULL DEFAULT 0,
    bytes_extracted BIGINT NOT NULL DEFAULT 0,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS "{schema}".evidence_files (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    job_id UUID NOT NULL REFERENCES "{schema}".jobs(id) ON DELETE CASCADE,
    group_id UUID,
    relative_path TEXT,
    original_name TEXT NOT NULL,
    storage_uri TEXT,
    mime_type TEXT,
    sha256 TEXT,
    status VARCHAR(32) NOT NULL DEFAULT 'registered',
    size_bytes BIGINT,
    host_path TEXT,
    source_kind VARCHAR(32) NOT NULL DEFAULT 'host',
    segment_part INTEGER,
    segment_base TEXT,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS "{schema}".disk_build_logs (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    job_id UUID NOT NULL REFERENCES "{schema}".jobs(id) ON DELETE CASCADE,
    timestamp TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    stage VARCHAR(64) NOT NULL DEFAULT 'build',
    level VARCHAR(16) NOT NULL DEFAULT 'info',
    message TEXT NOT NULL,
    metadata JSONB
);

CREATE TABLE IF NOT EXISTS "{schema}".pipeline_heal_events (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    job_id UUID NOT NULL REFERENCES "{schema}".jobs(id) ON DELETE CASCADE,
    agent VARCHAR(32) NOT NULL,
    issue_code VARCHAR(64) NOT NULL,
    issue_detail TEXT,
    stage VARCHAR(64),
    remedy_code VARCHAR(64),
    remedy_detail TEXT,
    status VARCHAR(32) NOT NULL DEFAULT 'detected',
    metadata JSONB NOT NULL DEFAULT '{}'::jsonb,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    resolved_at TIMESTAMPTZ
);

CREATE INDEX IF NOT EXISTS ix_jobs_status ON "{schema}".jobs(status);
CREATE INDEX IF NOT EXISTS ix_evidence_job ON "{schema}".evidence_files(job_id);
CREATE INDEX IF NOT EXISTS ix_evidence_host_path ON "{schema}".evidence_files(job_id, host_path);
CREATE INDEX IF NOT EXISTS ix_disk_build_logs_job ON "{schema}".disk_build_logs(job_id, timestamp);
CREATE INDEX IF NOT EXISTS ix_pipeline_heal_job ON "{schema}".pipeline_heal_events(job_id, created_at DESC);
