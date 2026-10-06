-- AXIOM artifact inventory results + objective/procedure scope (per firm).

CREATE OR REPLACE FUNCTION public.apply_firm_axiom_inventory(schema_name text)
RETURNS VOID
LANGUAGE plpgsql
AS $$
BEGIN
    EXECUTE format($sql$
        CREATE TABLE IF NOT EXISTS %I.job_axiom_artifact_results (
            id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
            job_id UUID NOT NULL REFERENCES %I.jobs(id) ON DELETE CASCADE,
            artifact_id TEXT NOT NULL,
            artifact_count INTEGER NOT NULL DEFAULT 0,
            status TEXT NOT NULL DEFAULT 'pending',
            answer TEXT,
            error TEXT,
            count_domain TEXT,
            occurrence_count INTEGER,
            unique_count INTEGER,
            query_snapshot JSONB,
            parser_version TEXT,
            confidence TEXT,
            created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
            updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
            UNIQUE(job_id, artifact_id)
        )
    $sql$, schema_name, schema_name);

    -- Upgrade older firm schemas created before count-provenance columns existed.
    EXECUTE format(
        'ALTER TABLE %I.job_axiom_artifact_results ADD COLUMN IF NOT EXISTS count_domain TEXT',
        schema_name
    );
    EXECUTE format(
        'ALTER TABLE %I.job_axiom_artifact_results ADD COLUMN IF NOT EXISTS occurrence_count INTEGER',
        schema_name
    );
    EXECUTE format(
        'ALTER TABLE %I.job_axiom_artifact_results ADD COLUMN IF NOT EXISTS unique_count INTEGER',
        schema_name
    );
    EXECUTE format(
        'ALTER TABLE %I.job_axiom_artifact_results ADD COLUMN IF NOT EXISTS query_snapshot JSONB',
        schema_name
    );
    EXECUTE format(
        'ALTER TABLE %I.job_axiom_artifact_results ADD COLUMN IF NOT EXISTS parser_version TEXT',
        schema_name
    );
    EXECUTE format(
        'ALTER TABLE %I.job_axiom_artifact_results ADD COLUMN IF NOT EXISTS confidence TEXT',
        schema_name
    );

    EXECUTE format($sql$
        CREATE TABLE IF NOT EXISTS %I.objective_procedure_scope (
            job_id UUID PRIMARY KEY REFERENCES %I.jobs(id) ON DELETE CASCADE,
            enabled_objective_ids JSONB NOT NULL DEFAULT '[]'::jsonb,
            custom_objectives JSONB NOT NULL DEFAULT '[]'::jsonb,
            updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
        )
    $sql$, schema_name, schema_name);

    EXECUTE format(
        'ALTER TABLE %I.objective_procedure_scope ADD COLUMN IF NOT EXISTS custom_objectives JSONB NOT NULL DEFAULT ''[]''::jsonb',
        schema_name
    );

    EXECUTE format(
        'CREATE INDEX IF NOT EXISTS ix_job_axiom_results_job ON %I.job_axiom_artifact_results(job_id)',
        schema_name
    );
END;
$$;

CREATE OR REPLACE FUNCTION public.apply_firm_axiom_inventory_all()
RETURNS VOID
LANGUAGE plpgsql
AS $$
DECLARE
    rec RECORD;
BEGIN
    FOR rec IN SELECT schema_name FROM public.firms WHERE status = 'active' LOOP
        PERFORM public.apply_firm_axiom_inventory(rec.schema_name);
    END LOOP;
END;
$$;

SELECT public.apply_firm_axiom_inventory_all();
