-- Laptop/edge scanner logs ingested over HTTPS from scanner-agent.
-- Usage: SELECT public.apply_firm_scanner_agent_logs('firm_acme');

CREATE OR REPLACE FUNCTION public.apply_firm_scanner_agent_logs(schema_name text)
RETURNS VOID AS $$
BEGIN
    EXECUTE format($sql$
        CREATE TABLE IF NOT EXISTS %I.scanner_agent_logs (
            id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
            scanner_id UUID,
            job_id UUID,
            level TEXT NOT NULL DEFAULT 'info',
            logger TEXT,
            stage TEXT,
            message TEXT NOT NULL,
            created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
        )
    $sql$, schema_name);

    EXECUTE format(
        'CREATE INDEX IF NOT EXISTS idx_scanner_agent_logs_created ON %I.scanner_agent_logs (created_at DESC)',
        schema_name
    );
    EXECUTE format(
        'CREATE INDEX IF NOT EXISTS idx_scanner_agent_logs_job ON %I.scanner_agent_logs (job_id)',
        schema_name
    );
    EXECUTE format(
        'CREATE INDEX IF NOT EXISTS idx_scanner_agent_logs_scanner ON %I.scanner_agent_logs (scanner_id, created_at DESC)',
        schema_name
    );
END;
$$ LANGUAGE plpgsql;

CREATE OR REPLACE FUNCTION public.apply_firm_scanner_agent_logs_all()
RETURNS VOID AS $$
DECLARE
    r RECORD;
BEGIN
    FOR r IN SELECT schema_name FROM public.firms WHERE schema_name IS NOT NULL LOOP
        PERFORM public.apply_firm_scanner_agent_logs(r.schema_name);
    END LOOP;
END;
$$ LANGUAGE plpgsql;

SELECT public.apply_firm_scanner_agent_logs_all();
