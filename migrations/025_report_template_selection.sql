-- Report template catalog (per report type) + per-job frozen selections for report generation.

CREATE TABLE IF NOT EXISTS public.reports_artifacts (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    report_type_id TEXT NOT NULL REFERENCES public.report_type_templates(report_type_id) ON DELETE CASCADE,
    artifact_id TEXT NOT NULL,
    category TEXT,
    artifact_name TEXT NOT NULL,
    description TEXT,
    sort_order INTEGER NOT NULL DEFAULT 0,
    default_enabled BOOLEAN NOT NULL DEFAULT TRUE,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    UNIQUE (report_type_id, artifact_id)
);

CREATE INDEX IF NOT EXISTS ix_reports_artifacts_type ON public.reports_artifacts (report_type_id, sort_order);

CREATE TABLE IF NOT EXISTS public.reports_objective (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    report_type_id TEXT NOT NULL REFERENCES public.report_type_templates(report_type_id) ON DELETE CASCADE,
    objective_id TEXT NOT NULL,
    title TEXT NOT NULL,
    objective TEXT,
    procedure_text TEXT,
    sort_order INTEGER NOT NULL DEFAULT 0,
    default_enabled BOOLEAN NOT NULL DEFAULT TRUE,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    UNIQUE (report_type_id, objective_id)
);

CREATE INDEX IF NOT EXISTS ix_reports_objective_type ON public.reports_objective (report_type_id, sort_order);

INSERT INTO public.report_type_templates
    (report_type_id, label, domain, description, default_os, sort_order)
VALUES
    ('policy_violation', 'Policy Violation Report', 'hr',
     'Workplace policy violations, unauthorized activity, and misconduct (RRP / Seger template).',
     ARRAY['windows'], 11)
ON CONFLICT (report_type_id) DO UPDATE SET
    label = EXCLUDED.label,
    domain = EXCLUDED.domain,
    description = EXCLUDED.description,
    default_os = EXCLUDED.default_os,
    sort_order = EXCLUDED.sort_order,
    updated_at = NOW();

UPDATE public.case_types
SET default_report_type_id = 'policy_violation'
WHERE case_type_id = 'workplace_misconduct';

-- ---------------------------------------------------------------------------
-- Per-firm job selection tables
-- ---------------------------------------------------------------------------
CREATE OR REPLACE FUNCTION public.apply_firm_report_template_selection(schema_name text)
RETURNS VOID
LANGUAGE plpgsql
AS $$
BEGIN
    EXECUTE format($sql$
        CREATE TABLE IF NOT EXISTS %I.selected_job_artifacts (
            job_id UUID PRIMARY KEY REFERENCES %I.jobs(id) ON DELETE CASCADE,
            report_type_id TEXT,
            artifact_ids JSONB NOT NULL DEFAULT '[]'::jsonb,
            artifacts_json JSONB NOT NULL DEFAULT '[]'::jsonb,
            saved_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
            updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
        )
    $sql$, schema_name, schema_name);

    EXECUTE format($sql$
        CREATE TABLE IF NOT EXISTS %I.selected_job_objectives_procedure (
            job_id UUID PRIMARY KEY REFERENCES %I.jobs(id) ON DELETE CASCADE,
            report_type_id TEXT,
            objective_ids JSONB NOT NULL DEFAULT '[]'::jsonb,
            custom_objectives JSONB NOT NULL DEFAULT '[]'::jsonb,
            objectives_json JSONB NOT NULL DEFAULT '[]'::jsonb,
            saved_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
            updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
        )
    $sql$, schema_name, schema_name);
END;
$$;

CREATE OR REPLACE FUNCTION public.apply_firm_report_template_selection_all()
RETURNS VOID
LANGUAGE plpgsql
AS $$
DECLARE
    r RECORD;
BEGIN
    FOR r IN SELECT schema_name FROM public.firms WHERE status = 'active'
    LOOP
        PERFORM public.apply_firm_report_template_selection(r.schema_name);
    END LOOP;
END;
$$;

SELECT public.apply_firm_report_template_selection_all();
