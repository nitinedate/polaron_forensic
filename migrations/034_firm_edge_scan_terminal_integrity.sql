-- Aetheris V2.5: only the edge-agent result ingest may complete an edge job.
--
-- A stale nessus-sync worker could race the laptop scanner, mark the row
-- completed, and set completed_at while the laptop OpenVAS task was still
-- running.  The verified edge evidence row is inserted before the legitimate
-- terminal job update, so this trigger is transaction-safe and idempotent.

CREATE OR REPLACE FUNCTION enforce_edge_scan_terminal_integrity()
RETURNS trigger
LANGUAGE plpgsql
AS $$
BEGIN
  IF lower(coalesce(NEW.status, '')) = 'completed'
     AND coalesce((NEW.orchestration_json->>'edge_agent')::boolean, false) = true
     AND NOT EXISTS (
       SELECT 1
       FROM vuln_scan_results r
       WHERE r.scan_job_id = NEW.id
         AND coalesce((r.result_json->>'edge_agent')::boolean, false) = true
         AND coalesce((r.result_json->>'assessment_complete')::boolean, false) = true
     )
  THEN
    NEW.status := 'running';
    NEW.completed_at := NULL;
  END IF;
  RETURN NEW;
END;
$$;

DROP TRIGGER IF EXISTS trg_edge_scan_terminal_integrity ON vuln_scan_jobs;

CREATE TRIGGER trg_edge_scan_terminal_integrity
BEFORE UPDATE OF status, completed_at ON vuln_scan_jobs
FOR EACH ROW
EXECUTE FUNCTION enforce_edge_scan_terminal_integrity();
