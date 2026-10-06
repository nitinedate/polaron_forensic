-- Step 11: Export manifest + Vol18 intake / chain-of-custody hooks.

CREATE OR REPLACE FUNCTION public.apply_firm_phase3_export_intake(schema_name text)
RETURNS VOID
LANGUAGE plpgsql
AS $$
BEGIN
    EXECUTE format(
        'ALTER TABLE %I.report_exports ADD COLUMN IF NOT EXISTS sha256 TEXT',
        schema_name
    );
    EXECUTE format(
        'ALTER TABLE %I.report_exports ADD COLUMN IF NOT EXISTS manifest_uri TEXT',
        schema_name
    );
    EXECUTE format(
        'ALTER TABLE %I.report_exports ADD COLUMN IF NOT EXISTS metadata JSONB DEFAULT ''{}''::jsonb',
        schema_name
    );
    EXECUTE format(
        'ALTER TABLE %I.case_intake ADD COLUMN IF NOT EXISTS requesting_agency TEXT',
        schema_name
    );
    EXECUTE format(
        'ALTER TABLE %I.case_intake ADD COLUMN IF NOT EXISTS case_number TEXT',
        schema_name
    );
    EXECUTE format(
        'ALTER TABLE %I.case_intake ADD COLUMN IF NOT EXISTS examiner_name TEXT',
        schema_name
    );
    EXECUTE format(
        'ALTER TABLE %I.case_intake ADD COLUMN IF NOT EXISTS lab_location TEXT',
        schema_name
    );
    EXECUTE format(
        'ALTER TABLE %I.case_intake ADD COLUMN IF NOT EXISTS evidence_received_date DATE',
        schema_name
    );
    EXECUTE format(
        'ALTER TABLE %I.case_intake ADD COLUMN IF NOT EXISTS chain_of_custody_ref TEXT',
        schema_name
    );
    EXECUTE format(
        'ALTER TABLE %I.case_intake ADD COLUMN IF NOT EXISTS vol18_form_json JSONB DEFAULT ''{}''::jsonb',
        schema_name
    );
END;
$$;

CREATE OR REPLACE FUNCTION public.apply_firm_phase3_export_intake_all()
RETURNS VOID
LANGUAGE plpgsql
AS $$
DECLARE
    r RECORD;
BEGIN
    FOR r IN SELECT schema_name FROM public.firms WHERE status = 'active'
    LOOP
        PERFORM public.apply_firm_phase3_export_intake(r.schema_name);
    END LOOP;
END;
$$;

SELECT public.apply_firm_phase3_export_intake_all();
