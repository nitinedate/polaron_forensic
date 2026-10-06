-- Job stop/resume controls and extraction checkpoint storage.

CREATE OR REPLACE FUNCTION public.apply_firm_job_control(schema_name text)
RETURNS VOID
LANGUAGE plpgsql
AS $$
BEGIN
    EXECUTE format(
        'ALTER TABLE %I.jobs ADD COLUMN IF NOT EXISTS stop_requested BOOLEAN NOT NULL DEFAULT FALSE',
        schema_name
    );
    EXECUTE format(
        'ALTER TABLE %I.jobs ADD COLUMN IF NOT EXISTS celery_task_id TEXT',
        schema_name
    );
    EXECUTE format(
        'ALTER TABLE %I.jobs ADD COLUMN IF NOT EXISTS extraction_checkpoint JSONB',
        schema_name
    );
END;
$$;

CREATE OR REPLACE FUNCTION public.apply_firm_job_control_all()
RETURNS VOID
LANGUAGE plpgsql
AS $$
DECLARE
    r RECORD;
BEGIN
    FOR r IN SELECT schema_name FROM public.firms WHERE schema_name IS NOT NULL LOOP
        PERFORM public.apply_firm_job_control(r.schema_name);
    END LOOP;
END;
$$;

SELECT public.apply_firm_job_control_all();
