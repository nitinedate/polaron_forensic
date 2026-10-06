-- Phase 2 forensic tables for existing firm schemas.

CREATE OR REPLACE FUNCTION public.apply_firm_forensic_phase2(schema_name text)
RETURNS VOID
LANGUAGE plpgsql
AS $$
BEGIN
    EXECUTE format($sql$
        CREATE TABLE IF NOT EXISTS %I.jobs (
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
        )
    $sql$, schema_name);

    -- Backfill columns when jobs already existed from an older/minimal schema.
    EXECUTE format(
        'ALTER TABLE %I.jobs ADD COLUMN IF NOT EXISTS domain_pack VARCHAR(64)',
        schema_name
    );
    EXECUTE format(
        'ALTER TABLE %I.jobs ADD COLUMN IF NOT EXISTS case_id UUID',
        schema_name
    );
    EXECUTE format(
        'ALTER TABLE %I.jobs ADD COLUMN IF NOT EXISTS created_by UUID',
        schema_name
    );
    EXECUTE format(
        'ALTER TABLE %I.jobs ADD COLUMN IF NOT EXISTS error TEXT',
        schema_name
    );
    EXECUTE format(
        'ALTER TABLE %I.jobs ADD COLUMN IF NOT EXISTS segment_readiness JSONB',
        schema_name
    );
    EXECUTE format(
        'ALTER TABLE %I.jobs ADD COLUMN IF NOT EXISTS disk_source JSONB',
        schema_name
    );
    EXECUTE format(
        'ALTER TABLE %I.jobs ADD COLUMN IF NOT EXISTS extracted_disk_uri TEXT',
        schema_name
    );
    EXECUTE format(
        'ALTER TABLE %I.jobs ADD COLUMN IF NOT EXISTS files_total INTEGER NOT NULL DEFAULT 0',
        schema_name
    );
    EXECUTE format(
        'ALTER TABLE %I.jobs ADD COLUMN IF NOT EXISTS files_extracted INTEGER NOT NULL DEFAULT 0',
        schema_name
    );
    EXECUTE format(
        'ALTER TABLE %I.jobs ADD COLUMN IF NOT EXISTS bytes_extracted BIGINT NOT NULL DEFAULT 0',
        schema_name
    );
    EXECUTE format(
        'ALTER TABLE %I.jobs ADD COLUMN IF NOT EXISTS created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()',
        schema_name
    );
    EXECUTE format(
        'ALTER TABLE %I.jobs ADD COLUMN IF NOT EXISTS updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()',
        schema_name
    );

    EXECUTE format($sql$
        CREATE TABLE IF NOT EXISTS %I.evidence_files (
            id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
            job_id UUID NOT NULL REFERENCES %I.jobs(id) ON DELETE CASCADE,
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
        )
    $sql$, schema_name, schema_name);

    EXECUTE format($sql$
        CREATE TABLE IF NOT EXISTS %I.disk_build_logs (
            id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
            job_id UUID NOT NULL REFERENCES %I.jobs(id) ON DELETE CASCADE,
            timestamp TIMESTAMPTZ NOT NULL DEFAULT NOW(),
            stage VARCHAR(64) NOT NULL DEFAULT 'build',
            level VARCHAR(16) NOT NULL DEFAULT 'info',
            message TEXT NOT NULL,
            metadata JSONB
        )
    $sql$, schema_name, schema_name);

    EXECUTE format('CREATE INDEX IF NOT EXISTS ix_jobs_status ON %I.jobs(status)', schema_name);
    EXECUTE format('CREATE INDEX IF NOT EXISTS ix_evidence_job ON %I.evidence_files(job_id)', schema_name);
    EXECUTE format(
        'CREATE INDEX IF NOT EXISTS ix_evidence_host_path ON %I.evidence_files(job_id, host_path)',
        schema_name
    );
    EXECUTE format(
        'CREATE INDEX IF NOT EXISTS ix_disk_build_logs_job ON %I.disk_build_logs(job_id, timestamp)',
        schema_name
    );
END;
$$;

CREATE OR REPLACE FUNCTION public.apply_firm_forensic_phase2_all()
RETURNS VOID
LANGUAGE plpgsql
AS $$
DECLARE
    rec RECORD;
BEGIN
    FOR rec IN SELECT schema_name FROM public.firms LOOP
        PERFORM public.apply_firm_forensic_phase2(rec.schema_name);
    END LOOP;
END;
$$;

SELECT public.apply_firm_forensic_phase2_all();
