-- AXIOM count provenance, investigation-area mapping, structured observations, reconciliation stub.

CREATE TABLE IF NOT EXISTS public.investigation_area_templates (
    area_code TEXT PRIMARY KEY,
    header_title TEXT NOT NULL,
    description TEXT,
    default_objective_id TEXT,
    sort_order INTEGER NOT NULL DEFAULT 0,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS public.artifact_investigation_area_map (
    artifact_id TEXT NOT NULL REFERENCES public.axiom_artifacts(artifact_id) ON DELETE CASCADE,
    area_code TEXT NOT NULL REFERENCES public.investigation_area_templates(area_code) ON DELETE CASCADE,
    PRIMARY KEY (artifact_id, area_code)
);

CREATE INDEX IF NOT EXISTS ix_artifact_investigation_area ON public.artifact_investigation_area_map (area_code);

INSERT INTO public.investigation_area_templates (area_code, header_title, description, sort_order)
VALUES
    ('USB_EXTERNAL_DEVICES', 'USB and External Device Usage', 'Connection and usage of removable storage.', 1),
    ('FILE_ACCESS_HANDLING', 'File Access and Handling', 'User file open, copy, and delete activity.', 2),
    ('USER_ACCOUNT_ACTIVITY', 'User Account Activity', 'Logons, profiles, and account changes.', 3),
    ('COMMUNICATION_MESSAGING', 'Communication and Messaging', 'Chat, social, and messaging artifacts.', 4),
    ('EMAIL_ACTIVITY', 'Email Activity', 'Local and webmail email artifacts.', 5),
    ('WEB_BROWSING', 'Web Browsing', 'Browser history, downloads, and cached content.', 6),
    ('MALWARE_SECURITY', 'Malware and Security Events', 'Defender, event logs, and malicious URLs.', 7),
    ('CLOUD_REMOTE_STORAGE', 'Cloud and Remote Storage', 'Sync clients and remote storage activity.', 8),
    ('DATA_EXFILTRATION', 'Data Exfiltration Indicators', 'Staging, upload, and transfer indicators.', 9),
    ('APPLICATION_USAGE', 'Application Usage', 'Installed programs, jump lists, and feature usage.', 10)
ON CONFLICT (area_code) DO UPDATE SET
    header_title = EXCLUDED.header_title,
    description = EXCLUDED.description,
    sort_order = EXCLUDED.sort_order,
    updated_at = NOW();

-- Map report-template and common Windows artifacts to investigation areas (category-driven seed).
INSERT INTO public.artifact_investigation_area_map (artifact_id, area_code)
SELECT aa.artifact_id, 'USB_EXTERNAL_DEVICES'
FROM public.axiom_artifacts aa
WHERE aa.category ILIKE '%Connected Devices%'
ON CONFLICT DO NOTHING;

INSERT INTO public.artifact_investigation_area_map (artifact_id, area_code)
SELECT aa.artifact_id, 'EMAIL_ACTIVITY'
FROM public.axiom_artifacts aa
WHERE aa.category ILIKE '%Email%'
ON CONFLICT DO NOTHING;

INSERT INTO public.artifact_investigation_area_map (artifact_id, area_code)
SELECT aa.artifact_id, 'COMMUNICATION_MESSAGING'
FROM public.axiom_artifacts aa
WHERE aa.category ILIKE '%Communication%'
ON CONFLICT DO NOTHING;

INSERT INTO public.artifact_investigation_area_map (artifact_id, area_code)
SELECT aa.artifact_id, 'FILE_ACCESS_HANDLING'
FROM public.axiom_artifacts aa
WHERE aa.category ILIKE '%Documents%'
ON CONFLICT DO NOTHING;

INSERT INTO public.artifact_investigation_area_map (artifact_id, area_code)
SELECT aa.artifact_id, 'APPLICATION_USAGE'
FROM public.axiom_artifacts aa
WHERE aa.category ILIKE '%Application Usage%'
ON CONFLICT DO NOTHING;

INSERT INTO public.artifact_investigation_area_map (artifact_id, area_code)
SELECT aa.artifact_id, 'WEB_BROWSING'
FROM public.axiom_artifacts aa
WHERE aa.category ILIKE '%Web Related%'
ON CONFLICT DO NOTHING;

INSERT INTO public.artifact_investigation_area_map (artifact_id, area_code)
SELECT aa.artifact_id, 'MALWARE_SECURITY'
FROM public.axiom_artifacts aa
WHERE aa.artifact_name ILIKE '%defender%' OR aa.artifact_name ILIKE '%malware%' OR aa.artifact_name ILIKE '%phishing%'
ON CONFLICT DO NOTHING;

-- Extend firm job_axiom_artifact_results with count provenance columns.
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

    EXECUTE format($sql$
        CREATE TABLE IF NOT EXISTS %I.job_objective_observations (
            id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
            job_id UUID NOT NULL REFERENCES %I.jobs(id) ON DELETE CASCADE,
            objective_id TEXT NOT NULL,
            status TEXT NOT NULL DEFAULT 'NOT_EXAMINED',
            structured_json JSONB NOT NULL DEFAULT '{}'::jsonb,
            observation_md TEXT,
            confidence TEXT,
            source_artifact_ids TEXT[] NOT NULL DEFAULT '{}',
            query_snapshot JSONB,
            created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
            updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
            UNIQUE(job_id, objective_id)
        )
    $sql$, schema_name, schema_name);

    EXECUTE format($sql$
        CREATE TABLE IF NOT EXISTS %I.job_count_reconciliation (
            id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
            job_id UUID NOT NULL REFERENCES %I.jobs(id) ON DELETE CASCADE,
            artifact_id TEXT NOT NULL,
            axiom_export_count INTEGER,
            python_inventory_count INTEGER,
            delta INTEGER,
            delta_reason TEXT,
            query_snapshot JSONB,
            created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
            updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
            UNIQUE(job_id, artifact_id)
        )
    $sql$, schema_name, schema_name);

    EXECUTE format(
        'CREATE INDEX IF NOT EXISTS ix_job_axiom_results_job ON %I.job_axiom_artifact_results(job_id)',
        schema_name
    );
    EXECUTE format(
        'CREATE INDEX IF NOT EXISTS ix_job_objective_obs_job ON %I.job_objective_observations(job_id)',
        schema_name
    );
    EXECUTE format(
        'CREATE INDEX IF NOT EXISTS ix_job_count_reconciliation_job ON %I.job_count_reconciliation(job_id)',
        schema_name
    );
END;
$$;

SELECT public.apply_firm_axiom_inventory_all();

-- Seed count-domain metadata on priority Windows artifacts (DOCX §1–3 contract).
UPDATE public.axiom_artifacts SET metadata = metadata || '{"count_domain":"artifact_record","record_unit":"registry_value","query_key":"USB_REGISTRY_SETUPAPI","parser_family":"registry","axiom_reconciliation_group":"USB_DEVICES"}'::jsonb, updated_at = NOW()
WHERE artifact_name ILIKE 'USB Devices%';

UPDATE public.axiom_artifacts SET metadata = metadata || '{"count_domain":"artifact_record","record_unit":"connection","query_key":"RDP_REGISTRY","parser_family":"registry"}'::jsonb, updated_at = NOW()
WHERE artifact_name ILIKE '%Remote Desktop%';

UPDATE public.axiom_artifacts SET metadata = metadata || '{"count_domain":"file_occurrence","record_unit":"file_entry","query_key":"DOCUMENT_EXTENSION","parser_family":"path_inventory"}'::jsonb, updated_at = NOW()
WHERE category = 'Documents';

UPDATE public.axiom_artifacts SET metadata = metadata || '{"count_domain":"artifact_record","record_unit":"visit","query_key":"URL_VISIT_CATEGORY","parser_family":"sqlite"}'::jsonb, updated_at = NOW()
WHERE category = 'Communication' AND artifact_name ILIKE '%URL%';

UPDATE public.axiom_artifacts SET metadata = metadata || '{"count_domain":"artifact_record","record_unit":"message","query_key":"OUTLOOK_EMAIL_WHERE","parser_family":"sqlite"}'::jsonb, updated_at = NOW()
WHERE category ILIKE '%Email%';

UPDATE public.axiom_artifacts SET metadata = metadata || '{"count_domain":"file_occurrence","record_unit":"file_entry","query_key":"JUMP_LIST_WHERE","parser_family":"path_inventory"}'::jsonb, updated_at = NOW()
WHERE artifact_name ILIKE '%Jump List%';

UPDATE public.axiom_artifacts SET metadata = metadata || '{"count_domain":"file_occurrence","record_unit":"file_entry","query_key":"LNK_WHERE","parser_family":"path_inventory"}'::jsonb, updated_at = NOW()
WHERE artifact_name ILIKE '%LNK%';

UPDATE public.axiom_artifacts SET metadata = metadata || '{"count_domain":"file_occurrence","record_unit":"file_entry","query_key":"LOGFILE_ANALYSIS_WHERE","parser_family":"path_inventory"}'::jsonb, updated_at = NOW()
WHERE artifact_name ILIKE '%Logfile%';
