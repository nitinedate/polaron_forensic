-- Firm-scoped self-healing ledger: Observe / Repair / Performance agents.
-- Applied at runtime via firm_migrations.ensure_pipeline_heal_events.

CREATE OR REPLACE FUNCTION public.apply_firm_pipeline_heal(p_schema text)
RETURNS void
LANGUAGE plpgsql
AS $$
BEGIN
  EXECUTE format($fmt$
    CREATE TABLE IF NOT EXISTS %I.pipeline_heal_events (
      id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
      job_id UUID NOT NULL REFERENCES %I.jobs(id) ON DELETE CASCADE,
      agent VARCHAR(32) NOT NULL,
      issue_code VARCHAR(64) NOT NULL,
      issue_detail TEXT,
      stage VARCHAR(64),
      remedy_code VARCHAR(64),
      remedy_detail TEXT,
      status VARCHAR(32) NOT NULL DEFAULT 'detected',
      metadata JSONB NOT NULL DEFAULT '{}'::jsonb,
      created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
      resolved_at TIMESTAMPTZ
    )
  $fmt$, p_schema, p_schema);

  EXECUTE format(
    'CREATE INDEX IF NOT EXISTS ix_pipeline_heal_job ON %I.pipeline_heal_events(job_id, created_at DESC)',
    p_schema
  );
  EXECUTE format(
    'CREATE INDEX IF NOT EXISTS ix_pipeline_heal_status ON %I.pipeline_heal_events(job_id, status)',
    p_schema
  );
END;
$$;
