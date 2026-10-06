-- Firm-scoped browser scanner network tokens (CIDR-bound, no laptop agent).

DROP FUNCTION IF EXISTS public.apply_firm_vuln_network_tokens(text);

CREATE OR REPLACE FUNCTION public.apply_firm_vuln_network_tokens(schema_name text)
RETURNS void
LANGUAGE plpgsql
AS $fn$
BEGIN
  EXECUTE format(
    $ddl$
    CREATE TABLE IF NOT EXISTS %I.vuln_network_tokens (
      id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
      name TEXT NOT NULL,
      cidr TEXT NOT NULL,
      note TEXT,
      authorization_ref TEXT,
      token_hash TEXT NOT NULL UNIQUE,
      token_hint TEXT,
      status TEXT NOT NULL DEFAULT 'issued',
      connected_public_ip TEXT,
      connected_at TIMESTAMPTZ,
      connected_by UUID,
      created_by UUID,
      expires_at TIMESTAMPTZ,
      created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
      updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
    )
    $ddl$,
    schema_name
  );
  EXECUTE format(
    'CREATE INDEX IF NOT EXISTS vuln_network_tokens_status_idx ON %I.vuln_network_tokens (status)',
    schema_name
  );
  EXECUTE format(
    'CREATE INDEX IF NOT EXISTS vuln_network_tokens_connected_by_idx ON %I.vuln_network_tokens (connected_by)',
    schema_name
  );
EXCEPTION WHEN undefined_object THEN
  NULL;
END;
$fn$;
