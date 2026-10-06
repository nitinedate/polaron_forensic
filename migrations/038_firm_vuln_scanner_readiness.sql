-- Edge scanner operational readiness reported by the laptop/persistent agent.
-- Usage: SELECT public.apply_firm_vuln_scanner_readiness('firm_acme');

CREATE OR REPLACE FUNCTION public.apply_firm_vuln_scanner_readiness(schema_name text)
RETURNS VOID AS $$
BEGIN
    EXECUTE format($sql$
        ALTER TABLE %I.vuln_scanners
            ADD COLUMN IF NOT EXISTS openvas_ready BOOLEAN,
            ADD COLUMN IF NOT EXISTS agent_status_detail TEXT,
            ADD COLUMN IF NOT EXISTS openvas_ready_at TIMESTAMPTZ
    $sql$, schema_name);

    EXECUTE format($sql$
        COMMENT ON COLUMN %I.vuln_scanners.openvas_ready IS
          'True only when the edge scanner reports Greenbone/OpenVAS feed and scan configuration ready'
    $sql$, schema_name);
END;
$$ LANGUAGE plpgsql;

CREATE OR REPLACE FUNCTION public.apply_firm_vuln_scanner_readiness_all()
RETURNS VOID AS $$
DECLARE
    r RECORD;
BEGIN
    FOR r IN SELECT schema_name FROM public.firms WHERE schema_name IS NOT NULL LOOP
        PERFORM public.apply_firm_vuln_scanner_readiness(r.schema_name);
    END LOOP;
END;
$$ LANGUAGE plpgsql;

SELECT public.apply_firm_vuln_scanner_readiness_all();
