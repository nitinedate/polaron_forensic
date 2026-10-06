-- Multi-scanner orchestration, correlation, and report fields (solution-set CSV compatible).
-- Usage: SELECT public.apply_firm_vuln_orchestrator('firm_acme');

CREATE OR REPLACE FUNCTION public.apply_firm_vuln_orchestrator(schema_name text)
RETURNS VOID AS $$
BEGIN
    EXECUTE format($sql$
        CREATE TABLE IF NOT EXISTS %I.vuln_scan_engine_runs (
            id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
            scan_job_id UUID NOT NULL REFERENCES %I.vuln_scan_jobs(id) ON DELETE CASCADE,
            engine TEXT NOT NULL,
            role TEXT,
            status TEXT NOT NULL DEFAULT 'pending',
            started_at TIMESTAMPTZ,
            completed_at TIMESTAMPTZ,
            findings_count INT NOT NULL DEFAULT 0,
            error TEXT,
            metadata_json JSONB,
            created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
        )
    $sql$, schema_name, schema_name);

    EXECUTE format($sql$
        CREATE TABLE IF NOT EXISTS %I.vuln_finding_correlations (
            id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
            case_id UUID NOT NULL,
            correlation_key TEXT NOT NULL,
            primary_finding_id UUID REFERENCES %I.vuln_findings(id) ON DELETE SET NULL,
            engine_count INT NOT NULL DEFAULT 1,
            engines_json JSONB,
            created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
            updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
            UNIQUE (case_id, correlation_key)
        )
    $sql$, schema_name, schema_name);

    EXECUTE format($sql$
        ALTER TABLE %I.vuln_scan_jobs
            ADD COLUMN IF NOT EXISTS orchestration_json JSONB
    $sql$, schema_name);

    EXECUTE format($sql$
        ALTER TABLE %I.vuln_findings
            ADD COLUMN IF NOT EXISTS description TEXT,
            ADD COLUMN IF NOT EXISTS scan_engine TEXT,
            ADD COLUMN IF NOT EXISTS correlation_key TEXT
    $sql$, schema_name);
END;
$$ LANGUAGE plpgsql;
