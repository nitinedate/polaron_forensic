-- Run after SET search_path to the affected firm schema.
-- Replace the UUID below with the scan job shown in the UI.
\set scan_job_id '00000000-0000-0000-0000-000000000000'

SELECT severity, count(*) AS findings,
       min(cvss) AS min_cvss, max(cvss) AS max_cvss
FROM vuln_findings
WHERE scan_job_id = :'scan_job_id'::uuid
GROUP BY severity
ORDER BY CASE lower(severity)
  WHEN 'critical' THEN 1 WHEN 'high' THEN 2 WHEN 'medium' THEN 3
  WHEN 'low' THEN 4 ELSE 5 END;

SELECT id, severity, cvss, synopsis, plugin_id, port, protocol,
       risk_factors_json ->> 'quality_of_detection' AS qod,
       risk_factors_json ->> 'quality_of_detection_type' AS qod_type
FROM vuln_findings
WHERE scan_job_id = :'scan_job_id'::uuid
ORDER BY cvss DESC NULLS LAST, severity, synopsis;

SELECT result_json ->> 'report_id' AS report_id,
       result_json ->> 'report_result_count' AS raw_report_rows,
       result_json ->> 'uploaded_vulnerability_rows' AS uploaded_rows,
       result_json ->> 'result_payload_ok' AS result_payload_ok,
       result_json ->> 'assessment_verdict' AS assessment_verdict,
       result_json ->> 'report_read_error' AS report_read_error
FROM vuln_scan_results
WHERE scan_job_id = :'scan_job_id'::uuid;
