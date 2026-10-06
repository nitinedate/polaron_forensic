-- Purge all jobs and cascaded associated data in every firm_* schema.
DO $$
DECLARE
  r record;
  t text;
BEGIN
  FOR r IN
    SELECT nspname FROM pg_namespace WHERE nspname LIKE 'firm_%' ORDER BY nspname
  LOOP
    -- Detach case links, then drop case-owned vuln rows
    BEGIN
      EXECUTE format('UPDATE %I.cases SET job_id = NULL WHERE job_id IS NOT NULL', r.nspname);
    EXCEPTION WHEN undefined_table OR undefined_column THEN
      NULL;
    END;
    FOREACH t IN ARRAY ARRAY[
      'vuln_scan_engine_runs', 'vuln_scan_results', 'vuln_scan_targets',
      'vuln_finding_correlations', 'vuln_remediation_tasks', 'vuln_exceptions',
      'vuln_timeline_events', 'vuln_asset_identifiers', 'vuln_findings',
      'vuln_assets', 'vuln_scan_policies'
    ]
    LOOP
      BEGIN
        EXECUTE format('DELETE FROM %I.%I', r.nspname, t);
      EXCEPTION WHEN undefined_table THEN
        NULL;
      END;
    END LOOP;

    -- Agent / report / image-evidence trees (best-effort)
    FOREACH t IN ARRAY ARRAY[
      'agent_tool_calls', 'agent_messages', 'agent_runs', 'agent_threads',
      'report_exports', 'report_citations', 'report_findings', 'report_sections', 'report_runs',
      'vuln_scan_jobs', 'vuln_pentest_jobs',
      'rag_image_embeddings', 'rag_image_assets', 'rag_selection_manifest_items', 'rag_selection_sessions'
    ]
    LOOP
      BEGIN
        EXECUTE format('DELETE FROM %I.%I', r.nspname, t);
      EXCEPTION WHEN undefined_table THEN
        NULL;
      END;
    END LOOP;

    -- Jobs (CASCADE clears most children)
    BEGIN
      EXECUTE format('DELETE FROM %I.jobs', r.nspname);
    EXCEPTION WHEN undefined_table THEN
      NULL;
    END;

    -- Orphans / leftover job content
    FOREACH t IN ARRAY ARRAY[
      'rag_chunks', 'rag_retrieval_log', 'job_artifacts', 'evidence_files',
      'job_axiom_artifact_results', 'job_objective_observations', 'job_count_reconciliation',
      'job_artifact_groups', 'disk_build_logs', 'parser_runs', 'timeline_events',
      'case_intake', 'artifact_scope', 'graph_sync_state', 'objective_procedure_scope',
      'pipeline_heal_events', 'artifact_parse_results', 'ocr_results',
      'selected_job_artifacts', 'selected_job_objectives_procedure'
    ]
    LOOP
      BEGIN
        EXECUTE format('DELETE FROM %I.%I', r.nspname, t);
      EXCEPTION WHEN undefined_table THEN
        NULL;
      END;
    END LOOP;

    BEGIN
      EXECUTE format('DELETE FROM %I.cases', r.nspname);
    EXCEPTION WHEN undefined_table THEN
      NULL;
    END;
    BEGIN
      EXECUTE format(
        'INSERT INTO %I.cases (id, title, status, timezone, created_at, updated_at)
         VALUES (''00000000-0000-4000-8000-000000000001''::uuid, ''Default workspace'', ''open'', ''UTC'', NOW(), NOW())
         ON CONFLICT (id) DO NOTHING',
        r.nspname
      );
    EXCEPTION WHEN undefined_table THEN
      NULL;
    END;

    RAISE NOTICE 'purged schema %', r.nspname;
  END LOOP;
END $$;

-- Verification (skip missing schemas/tables)
DO $$
DECLARE
  r record;
  n bigint;
BEGIN
  FOR r IN
    SELECT nspname FROM pg_namespace WHERE nspname LIKE 'firm_%' ORDER BY nspname
  LOOP
    BEGIN
      EXECUTE format('SELECT count(*) FROM %I.jobs', r.nspname) INTO n;
      RAISE NOTICE '% jobs = %', r.nspname, n;
    EXCEPTION WHEN undefined_table THEN
      RAISE NOTICE '% jobs table missing', r.nspname;
    END;
    BEGIN
      EXECUTE format('SELECT count(*) FROM %I.cases', r.nspname) INTO n;
      RAISE NOTICE '% cases = %', r.nspname, n;
    EXCEPTION WHEN undefined_table THEN
      NULL;
    END;
    BEGIN
      EXECUTE format('SELECT count(*) FROM %I.job_artifacts', r.nspname) INTO n;
      RAISE NOTICE '% job_artifacts = %', r.nspname, n;
    EXCEPTION WHEN undefined_table THEN
      NULL;
    END;
    BEGIN
      EXECUTE format('SELECT count(*) FROM %I.evidence_files', r.nspname) INTO n;
      RAISE NOTICE '% evidence_files = %', r.nspname, n;
    EXCEPTION WHEN undefined_table THEN
      NULL;
    END;
    BEGIN
      EXECUTE format('SELECT count(*) FROM %I.rag_chunks', r.nspname) INTO n;
      RAISE NOTICE '% rag_chunks = %', r.nspname, n;
    EXCEPTION WHEN undefined_table THEN
      NULL;
    END;
    BEGIN
      EXECUTE format('SELECT count(*) FROM %I.rag_selection_sessions', r.nspname) INTO n;
      RAISE NOTICE '% rag_selection_sessions = %', r.nspname, n;
    EXCEPTION WHEN undefined_table THEN
      NULL;
    END;
    BEGIN
      EXECUTE format('SELECT count(*) FROM %I.rag_image_assets', r.nspname) INTO n;
      RAISE NOTICE '% rag_image_assets = %', r.nspname, n;
    EXCEPTION WHEN undefined_table THEN
      NULL;
    END;
  END LOOP;
END $$;
