-- Workspace / case records for vuln scans and forensic grouping.
-- Usage: SELECT public.apply_firm_cases('firm_acme');

CREATE OR REPLACE FUNCTION public.apply_firm_cases(schema_name text)
RETURNS VOID AS $$
BEGIN
    EXECUTE format($sql$
        CREATE TABLE IF NOT EXISTS %I.cases (
            id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
            job_id UUID,
            number TEXT,
            title TEXT NOT NULL DEFAULT 'Untitled case',
            status TEXT NOT NULL DEFAULT 'open',
            classification TEXT,
            timezone TEXT NOT NULL DEFAULT 'UTC',
            owner_id UUID,
            authorization_notes TEXT,
            created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
            updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
        )
    $sql$, schema_name);
    EXECUTE format(
        'ALTER TABLE %I.cases ADD COLUMN IF NOT EXISTS gap_site_json JSONB DEFAULT ''{}''::jsonb',
        schema_name
    );
END;
$$ LANGUAGE plpgsql;
