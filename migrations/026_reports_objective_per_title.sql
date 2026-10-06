-- Per-title report objectives: unique procedure per section title, AXIOM link for artifacts.

ALTER TABLE public.reports_objective
    ADD COLUMN IF NOT EXISTS axiom_objective_id TEXT;

CREATE INDEX IF NOT EXISTS ix_reports_objective_axiom_link
    ON public.reports_objective (axiom_objective_id)
    WHERE axiom_objective_id IS NOT NULL;

-- Allow multiple titles to share the same AXIOM workbook id (e.g. O018) while keeping one row per title.
ALTER TABLE public.reports_objective
    DROP CONSTRAINT IF EXISTS reports_objective_report_type_id_objective_id_key;

CREATE UNIQUE INDEX IF NOT EXISTS uq_reports_objective_type_title
    ON public.reports_objective (report_type_id, lower(trim(title)));

-- Per-title RPT-O9xx ids remain unique per report type (required for upsert).
ALTER TABLE public.reports_objective
    DROP CONSTRAINT IF EXISTS reports_objective_report_type_id_objective_id_key;

ALTER TABLE public.reports_objective
    ADD CONSTRAINT reports_objective_report_type_id_objective_id_key
    UNIQUE (report_type_id, objective_id);
