-- Allow encyclopedia knowledge chunks (shared across jobs) with job_id IS NULL.

CREATE OR REPLACE FUNCTION public.apply_firm_phase3_fixes(schema_name text)
RETURNS VOID
LANGUAGE plpgsql
AS $$
BEGIN
    -- Encyclopedia chunks are job-agnostic; dual_rag_index inserts job_id=NULL rows.
    EXECUTE format(
        'ALTER TABLE %I.rag_chunks ALTER COLUMN job_id DROP NOT NULL',
        schema_name
    );
EXCEPTION
    WHEN others THEN
        -- Column may already be nullable on fresh schemas.
        NULL;
END;
$$;

CREATE OR REPLACE FUNCTION public.apply_firm_phase3_fixes_all()
RETURNS VOID
LANGUAGE plpgsql
AS $$
DECLARE
    r RECORD;
BEGIN
    FOR r IN SELECT schema_name FROM public.firms WHERE status = 'active'
    LOOP
        PERFORM public.apply_firm_phase3_fixes(r.schema_name);
    END LOOP;
END;
$$;

SELECT public.apply_firm_phase3_fixes_all();
