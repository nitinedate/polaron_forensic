-- Firm-scoped scanner_role on vuln_scanners (portable / persistent_edge / remote_vpn / central).

DROP FUNCTION IF EXISTS public.apply_firm_vuln_scanner_role(text);

CREATE OR REPLACE FUNCTION public.apply_firm_vuln_scanner_role(schema_name text)
RETURNS void
LANGUAGE plpgsql
AS $fn$
BEGIN
  BEGIN
    EXECUTE format(
      'ALTER TABLE %I.vuln_scanners ADD COLUMN IF NOT EXISTS scanner_role TEXT',
      schema_name
    );
  EXCEPTION WHEN undefined_table THEN
    RETURN;
  END;
  BEGIN
    EXECUTE format(
      'UPDATE %I.vuln_scanners
          SET scanner_role = CASE
            WHEN lower(coalesce(scanner_role, '''')) IN
                 (''portable'', ''persistent_edge'', ''remote_vpn'', ''central'')
              THEN scanner_role
            WHEN lower(coalesce(connection_mode, '''')) = ''edge_agent''
              OR lower(left(coalesce(url, ''''), 8)) = ''agent://''
              THEN ''portable''
            WHEN strpos(lower(coalesce(url, '''')), ''unix://'') = 1
              OR strpos(lower(coalesce(url, '''')), ''gvmd'') > 0
              THEN ''central''
            ELSE ''remote_vpn''
          END
        WHERE scanner_role IS NULL OR btrim(scanner_role) = ''''',
      schema_name
    );
  EXCEPTION WHEN undefined_column OR undefined_table THEN
    NULL;
  END;
END;
$fn$;
