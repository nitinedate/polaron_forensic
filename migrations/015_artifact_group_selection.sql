-- Per-job artifact group selection (group name, artifacts, counts, descriptions).

CREATE OR REPLACE FUNCTION public.apply_firm_artifact_group_selection(schema_name text)
RETURNS VOID
LANGUAGE plpgsql
AS $$
BEGIN
    EXECUTE format($sql$
        CREATE TABLE IF NOT EXISTS %I.job_artifact_groups (
            job_id UUID NOT NULL REFERENCES %I.jobs(id) ON DELETE CASCADE,
            group_name TEXT NOT NULL,
            group_count INTEGER NOT NULL DEFAULT 0,
            group_description TEXT,
            enabled BOOLEAN NOT NULL DEFAULT TRUE,
            artifacts JSONB NOT NULL DEFAULT '[]'::jsonb,
            updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
            PRIMARY KEY (job_id, group_name)
        )
    $sql$, schema_name, schema_name);

    EXECUTE format(
        'CREATE INDEX IF NOT EXISTS idx_%I_job_artifact_groups_job ON %I.job_artifact_groups(job_id)',
        schema_name, schema_name
    );
END;
$$;

CREATE OR REPLACE FUNCTION public.apply_firm_artifact_group_selection_all()
RETURNS VOID
LANGUAGE plpgsql
AS $$
DECLARE
    r RECORD;
BEGIN
    FOR r IN SELECT schema_name FROM public.firms WHERE status = 'active'
    LOOP
        PERFORM public.apply_firm_artifact_group_selection(r.schema_name);
    END LOOP;
END;
$$;

SELECT public.apply_firm_artifact_group_selection_all();
