-- Scanner deployment class: persistent_edge | portable | remote_vpn (plus inferred central).
-- Usage: SELECT public.apply_firm_vuln_scanner_role('firm_acme');

CREATE OR REPLACE FUNCTION public.apply_firm_vuln_scanner_role(schema_name text)
RETURNS VOID AS $$
BEGIN
    EXECUTE format($sql$
        ALTER TABLE %I.vuln_scanners
            ADD COLUMN IF NOT EXISTS scanner_role TEXT
    $sql$, schema_name);

    EXECUTE format($sql$
        UPDATE %I.vuln_scanners
           SET scanner_role = 'portable'
         WHERE scanner_role IS NULL
           AND lower(COALESCE(connection_mode, 'gmp')) = 'edge_agent'
    $sql$, schema_name);

    EXECUTE format($sql$
        UPDATE %I.vuln_scanners
           SET scanner_role = 'remote_vpn'
         WHERE scanner_role IS NULL
           AND lower(COALESCE(connection_mode, 'gmp')) = 'gmp'
           AND url IS NOT NULL
           AND url !~* '^(unix:|gmp://gvmd|tls://gvmd|agent:)'
           AND url NOT LIKE 'unix://%%'
    $sql$, schema_name);

    EXECUTE format($sql$
        COMMENT ON COLUMN %I.vuln_scanners.scanner_role IS
          'persistent_edge | portable | remote_vpn | central (inferred for local GMP)'
    $sql$, schema_name);
END;
$$ LANGUAGE plpgsql;

CREATE OR REPLACE FUNCTION public.apply_firm_vuln_scanner_role_all()
RETURNS VOID AS $$
DECLARE
    r RECORD;
BEGIN
    FOR r IN SELECT schema_name FROM public.firms WHERE schema_name IS NOT NULL LOOP
        PERFORM public.apply_firm_vuln_scanner_role(r.schema_name);
    END LOOP;
END;
$$ LANGUAGE plpgsql;

SELECT public.apply_firm_vuln_scanner_role_all();
