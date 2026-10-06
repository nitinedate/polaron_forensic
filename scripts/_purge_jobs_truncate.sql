-- Fast purge: truncate jobs (CASCADE clears related child tables).
UPDATE firm_aetheris.cases SET job_id = NULL WHERE job_id IS NOT NULL;
TRUNCATE TABLE firm_aetheris.jobs RESTART IDENTITY CASCADE;

SELECT 'jobs=' || count(*)::text FROM firm_aetheris.jobs;
SELECT 'artifacts=' || count(*)::text FROM firm_aetheris.job_artifacts;
SELECT 'chunks=' || count(*)::text FROM firm_aetheris.rag_chunks;
SELECT 'logs=' || count(*)::text FROM firm_aetheris.disk_build_logs;
SELECT 'ocr=' || count(*)::text FROM firm_aetheris.ocr_results;
SELECT 'parse=' || count(*)::text FROM firm_aetheris.artifact_parse_results;
SELECT 'graph=' || count(*)::text FROM firm_aetheris.graph_sync_state;
