-- Durable edge-agent token recovery + 24h previous-token grace.
-- Usage: SELECT public.apply_firm_vuln_edge_agent_recovery('firm_acme');

CREATE OR REPLACE FUNCTION public.apply_firm_vuln_edge_agent_recovery(schema_name text)
RETURNS VOID AS $$
BEGIN
    EXECUTE format($sql$
        ALTER TABLE %I.vuln_scanners
            ADD COLUMN IF NOT EXISTS agent_recovery_token_hash TEXT,
            ADD COLUMN IF NOT EXISTS agent_previous_token_hash TEXT,
            ADD COLUMN IF NOT EXISTS agent_previous_token_valid_until TIMESTAMPTZ
    $sql$, schema_name);

    EXECUTE format($sql$
        CREATE INDEX IF NOT EXISTS vuln_scanners_agent_recovery_token_hash_idx
            ON %I.vuln_scanners (agent_recovery_token_hash)
            WHERE agent_recovery_token_hash IS NOT NULL
    $sql$, schema_name);
END;
$$ LANGUAGE plpgsql;

CREATE OR REPLACE FUNCTION public.apply_firm_vuln_edge_agent_recovery_all()
RETURNS VOID AS $$
DECLARE
    r RECORD;
BEGIN
    FOR r IN SELECT schema_name FROM public.firms WHERE schema_name IS NOT NULL LOOP
        PERFORM public.apply_firm_vuln_edge_agent_recovery(r.schema_name);
    END LOOP;
END;
$$ LANGUAGE plpgsql;

SELECT public.apply_firm_vuln_edge_agent_recovery_all();
