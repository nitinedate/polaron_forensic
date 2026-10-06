-- Edge scanner agent columns for on-site OpenVAS (HTTPS poll / push).
-- Usage: SELECT public.apply_firm_vuln_edge_agent('firm_acme');

CREATE OR REPLACE FUNCTION public.apply_firm_vuln_edge_agent(schema_name text)
RETURNS VOID AS $$
BEGIN
    EXECUTE format($sql$
        ALTER TABLE %I.vuln_scanners
            ADD COLUMN IF NOT EXISTS connection_mode TEXT NOT NULL DEFAULT 'gmp',
            ADD COLUMN IF NOT EXISTS agent_token_hash TEXT,
            ADD COLUMN IF NOT EXISTS agent_token_hint TEXT
    $sql$, schema_name);

    EXECUTE format($sql$
        CREATE INDEX IF NOT EXISTS vuln_scanners_agent_token_hash_idx
            ON %I.vuln_scanners (agent_token_hash)
            WHERE agent_token_hash IS NOT NULL
    $sql$, schema_name);
END;
$$ LANGUAGE plpgsql;

CREATE OR REPLACE FUNCTION public.apply_firm_vuln_edge_agent_all()
RETURNS VOID AS $$
DECLARE
    r RECORD;
BEGIN
    FOR r IN SELECT schema_name FROM public.firms WHERE schema_name IS NOT NULL LOOP
        PERFORM public.apply_firm_vuln_edge_agent(r.schema_name);
    END LOOP;
END;
$$ LANGUAGE plpgsql;

SELECT public.apply_firm_vuln_edge_agent_all();
