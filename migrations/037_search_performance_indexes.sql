-- V37 artifact explorer performance/index migration.
-- Moves all index creation out of GET /api/jobs/{id}/artifacts.
-- Safe to re-run; applies to every active firm schema.

DO $$
BEGIN
  BEGIN
    CREATE EXTENSION IF NOT EXISTS pg_trgm;
  EXCEPTION WHEN insufficient_privilege THEN
    RAISE NOTICE 'pg_trgm unavailable to migration user; trigram indexes will be skipped';
  END;
END $$;

CREATE OR REPLACE FUNCTION public.apply_firm_search_indexes_v1(p_schema text)
RETURNS void
LANGUAGE plpgsql
AS $fn$
BEGIN
  BEGIN
    EXECUTE format('CREATE INDEX IF NOT EXISTS ix_jobs_case_id ON %I.jobs (case_id)', p_schema);
  EXCEPTION WHEN undefined_table THEN NULL; END;

  BEGIN
    EXECUTE format(
      'CREATE TABLE IF NOT EXISTS %I.job_evidence_browse_cache (
         job_id uuid NOT NULL,
         cache_kind text NOT NULL,
         payload jsonb NOT NULL DEFAULT ''[]''::jsonb,
         updated_at timestamptz NOT NULL DEFAULT now(),
         PRIMARY KEY (job_id, cache_kind)
       )',
      p_schema
    );
  EXCEPTION WHEN undefined_table THEN NULL; END;

  BEGIN EXECUTE format('CREATE INDEX IF NOT EXISTS ix_job_artifacts_job_path ON %I.job_artifacts (job_id, file_path)', p_schema); EXCEPTION WHEN undefined_table THEN NULL; END;
  BEGIN EXECUTE format('CREATE INDEX IF NOT EXISTS ix_job_artifacts_job_file_name ON %I.job_artifacts (job_id, file_name)', p_schema); EXCEPTION WHEN undefined_table THEN NULL; END;
  BEGIN EXECUTE format('CREATE INDEX IF NOT EXISTS ix_job_artifacts_job_file_name_lower ON %I.job_artifacts (job_id, lower(file_name))', p_schema); EXCEPTION WHEN undefined_table THEN NULL; END;
  BEGIN EXECUTE format('CREATE INDEX IF NOT EXISTS ix_job_artifacts_job_ext ON %I.job_artifacts (job_id, lower(coalesce(extension, '''')))', p_schema); EXCEPTION WHEN undefined_table THEN NULL; END;
  BEGIN EXECUTE format('CREATE INDEX IF NOT EXISTS ix_job_artifacts_job_enc ON %I.job_artifacts (job_id, encyclopedia_artifact_id) WHERE encyclopedia_artifact_id IS NOT NULL', p_schema); EXCEPTION WHEN undefined_table THEN NULL; END;
  BEGIN EXECUTE format('CREATE INDEX IF NOT EXISTS ix_job_artifacts_job_size ON %I.job_artifacts (job_id, size_bytes DESC NULLS LAST)', p_schema); EXCEPTION WHEN undefined_table THEN NULL; END;
  BEGIN EXECUTE format('CREATE INDEX IF NOT EXISTS ix_job_artifacts_job_name_size ON %I.job_artifacts (job_id, lower(file_name), size_bytes DESC NULLS LAST)', p_schema); EXCEPTION WHEN undefined_table THEN NULL; END;
  BEGIN EXECUTE format('CREATE INDEX IF NOT EXISTS ix_job_artifacts_job_mime_resolved ON %I.job_artifacts (job_id, (metadata->>''resolved_content_type'')) WHERE metadata ? ''resolved_content_type''', p_schema); EXCEPTION WHEN undefined_table THEN NULL; END;
  BEGIN EXECUTE format('CREATE INDEX IF NOT EXISTS ix_job_artifacts_job_mime ON %I.job_artifacts (job_id, (metadata->>''content_type'')) WHERE metadata ? ''content_type''', p_schema); EXCEPTION WHEN undefined_table THEN NULL; END;
  BEGIN EXECUTE format('CREATE INDEX IF NOT EXISTS ix_job_artifacts_job_mime_resolved_lower ON %I.job_artifacts (job_id, lower(coalesce(metadata->>''resolved_content_type'', '''')))', p_schema); EXCEPTION WHEN undefined_table THEN NULL; END;
  BEGIN EXECUTE format('CREATE INDEX IF NOT EXISTS ix_job_artifacts_job_mime_lower ON %I.job_artifacts (job_id, lower(coalesce(metadata->>''content_type'', '''')))', p_schema); EXCEPTION WHEN undefined_table THEN NULL; END;
  BEGIN EXECUTE format('CREATE INDEX IF NOT EXISTS ix_job_artifacts_job_mime_scan_version ON %I.job_artifacts (job_id, (metadata->>''mime_scan_version''))', p_schema); EXCEPTION WHEN undefined_table THEN NULL; END;

  BEGIN EXECUTE format('ALTER TABLE %I.job_axiom_artifact_results ADD COLUMN IF NOT EXISTS count_domain TEXT', p_schema); EXCEPTION WHEN undefined_table THEN NULL; END;
  BEGIN EXECUTE format('ALTER TABLE %I.job_axiom_artifact_results ADD COLUMN IF NOT EXISTS occurrence_count INTEGER', p_schema); EXCEPTION WHEN undefined_table THEN NULL; END;
  BEGIN EXECUTE format('ALTER TABLE %I.job_axiom_artifact_results ADD COLUMN IF NOT EXISTS unique_count INTEGER', p_schema); EXCEPTION WHEN undefined_table THEN NULL; END;
  BEGIN EXECUTE format('ALTER TABLE %I.job_axiom_artifact_results ADD COLUMN IF NOT EXISTS query_snapshot JSONB', p_schema); EXCEPTION WHEN undefined_table THEN NULL; END;
  BEGIN EXECUTE format('ALTER TABLE %I.job_axiom_artifact_results ADD COLUMN IF NOT EXISTS parser_version TEXT', p_schema); EXCEPTION WHEN undefined_table THEN NULL; END;
  BEGIN EXECUTE format('ALTER TABLE %I.job_axiom_artifact_results ADD COLUMN IF NOT EXISTS confidence TEXT', p_schema); EXCEPTION WHEN undefined_table THEN NULL; END;
  BEGIN
    EXECUTE format('CREATE TABLE IF NOT EXISTS %I.job_count_reconciliation (job_id UUID NOT NULL, artifact_id TEXT NOT NULL, axiom_export_count BIGINT, python_inventory_count BIGINT, delta BIGINT, delta_reason TEXT, query_snapshot JSONB NOT NULL DEFAULT ''{}''::jsonb, updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(), PRIMARY KEY (job_id, artifact_id))', p_schema);
  EXCEPTION WHEN undefined_table THEN NULL; END;
  BEGIN EXECUTE format('CREATE INDEX IF NOT EXISTS ix_job_artifacts_job_parse_pending ON %I.job_artifacts (job_id) WHERE parse_status = ''pending''', p_schema); EXCEPTION WHEN undefined_table THEN NULL; END;
  BEGIN EXECUTE format('CREATE INDEX IF NOT EXISTS ix_job_artifacts_job_ocr_pending ON %I.job_artifacts (job_id) WHERE ocr_status = ''pending''', p_schema); EXCEPTION WHEN undefined_table THEN NULL; END;

  BEGIN EXECUTE format('CREATE INDEX IF NOT EXISTS ix_artifact_parse_results_artifact_created ON %I.artifact_parse_results (job_artifact_id, created_at DESC)', p_schema); EXCEPTION WHEN undefined_table THEN NULL; END;
  BEGIN EXECUTE format('CREATE INDEX IF NOT EXISTS ix_artifact_parse_results_parser_artifact ON %I.artifact_parse_results (parser_name, job_artifact_id)', p_schema); EXCEPTION WHEN undefined_table THEN NULL; END;
  BEGIN EXECUTE format('CREATE INDEX IF NOT EXISTS ix_job_axiom_results_job_artifact_status ON %I.job_axiom_artifact_results (job_id, artifact_id, status)', p_schema); EXCEPTION WHEN undefined_table OR undefined_column THEN NULL; END;

  -- Accuracy/report hot paths for vulnerability results.  These predicates mirror
  -- the case/job-scoped collectors used by dashboards, report export and per-IP
  -- progress.  Composite indexes avoid broad severity/host scans across cases.
  BEGIN EXECUTE format('CREATE INDEX IF NOT EXISTS ix_vuln_findings_case_status_severity ON %I.vuln_findings (case_id, status, severity)', p_schema); EXCEPTION WHEN undefined_table OR undefined_column THEN NULL; END;
  BEGIN EXECUTE format('CREATE INDEX IF NOT EXISTS ix_vuln_findings_job_status ON %I.vuln_findings (scan_job_id, status)', p_schema); EXCEPTION WHEN undefined_table OR undefined_column THEN NULL; END;
  BEGIN EXECUTE format('CREATE INDEX IF NOT EXISTS ix_vuln_findings_asset_status ON %I.vuln_findings (asset_id, status)', p_schema); EXCEPTION WHEN undefined_table OR undefined_column THEN NULL; END;
  BEGIN EXECUTE format('CREATE INDEX IF NOT EXISTS ix_vuln_findings_case_port_proto ON %I.vuln_findings (case_id, port, protocol)', p_schema); EXCEPTION WHEN undefined_table OR undefined_column THEN NULL; END;
  BEGIN EXECUTE format('CREATE INDEX IF NOT EXISTS ix_vuln_assets_case_ip ON %I.vuln_assets (case_id, primary_ip)', p_schema); EXCEPTION WHEN undefined_table OR undefined_column THEN NULL; END;
  BEGIN EXECUTE format('CREATE INDEX IF NOT EXISTS ix_vuln_scan_targets_job_excluded_target ON %I.vuln_scan_targets (scan_job_id, excluded, target)', p_schema); EXCEPTION WHEN undefined_table OR undefined_column THEN NULL; END;
  BEGIN EXECUTE format('CREATE INDEX IF NOT EXISTS ix_vuln_scan_jobs_case_created ON %I.vuln_scan_jobs (case_id, created_at DESC)', p_schema); EXCEPTION WHEN undefined_table OR undefined_column THEN NULL; END;
  BEGIN EXECUTE format('CREATE INDEX IF NOT EXISTS ix_vuln_scan_results_job_created ON %I.vuln_scan_results (scan_job_id, created_at DESC)', p_schema); EXCEPTION WHEN undefined_table OR undefined_column THEN NULL; END;

  BEGIN
    EXECUTE format('CREATE INDEX IF NOT EXISTS ix_job_artifacts_path_trgm ON %I.job_artifacts USING gin (file_path gin_trgm_ops)', p_schema);
  EXCEPTION WHEN undefined_table OR undefined_object THEN NULL; END;
  BEGIN
    EXECUTE format('CREATE INDEX IF NOT EXISTS ix_job_artifacts_name_trgm ON %I.job_artifacts USING gin (file_name gin_trgm_ops)', p_schema);
  EXCEPTION WHEN undefined_table OR undefined_object THEN NULL; END;

  BEGIN EXECUTE format('ANALYZE %I.job_artifacts', p_schema); EXCEPTION WHEN undefined_table THEN NULL; END;
  BEGIN EXECUTE format('ANALYZE %I.vuln_findings', p_schema); EXCEPTION WHEN undefined_table THEN NULL; END;
  BEGIN EXECUTE format('ANALYZE %I.vuln_scan_targets', p_schema); EXCEPTION WHEN undefined_table THEN NULL; END;
END;
$fn$;

DO $$
DECLARE rec record;
BEGIN
  FOR rec IN SELECT schema_name FROM public.firms WHERE lower(coalesce(status, '')) = 'active' LOOP
    BEGIN
      PERFORM public.apply_firm_search_indexes_v1(rec.schema_name);
    EXCEPTION WHEN OTHERS THEN
      RAISE NOTICE 'artifact browse index apply skipped for %: %', rec.schema_name, SQLERRM;
    END;
  END LOOP;
END $$;
