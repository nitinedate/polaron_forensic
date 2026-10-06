-- Custom examiner objectives on objective_procedure_scope.

CREATE OR REPLACE FUNCTION public.apply_firm_axiom_custom_objectives(schema_name text)
RETURNS VOID
LANGUAGE plpgsql
AS $$
BEGIN
    EXECUTE format(
        'ALTER TABLE %I.objective_procedure_scope ADD COLUMN IF NOT EXISTS custom_objectives JSONB NOT NULL DEFAULT ''[]''::jsonb',
        schema_name
    );
END;
$$;

SELECT public.apply_firm_axiom_custom_objectives(schema_name)
FROM public.firms
WHERE status = 'active';
