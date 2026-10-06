@echo off
setlocal EnableExtensions
cd /d F:\rag_new2

set "JOB=%~1"
if "%JOB%"=="" set "JOB=3b24c156-f2e2-4f9c-b774-fc03731a12b2"
set "SCHEMA=firm_aetheris"
set "COMPOSE=docker-compose.https.yml"

echo ============================================================
echo Aetheris - Failed Scan Diagnostic (CENTRAL)
echo Job: %JOB%
echo ============================================================
echo READ-ONLY: no stop, restart, recreate, remove, prune, or volume changes.
echo.

echo [1/6] Job row + exact stored error
docker exec rag_new2-postgres-1 psql -U forensic -d forensic -P pager=off -x -c ^
"SELECT j.id,j.status,j.started_at,j.completed_at,j.external_scan_id,j.error,j.preflight_json,j.orchestration_json,j.scanner_id, to_jsonb(s) AS scanner FROM %SCHEMA%.vuln_scan_jobs j LEFT JOIN %SCHEMA%.vuln_scanners s ON s.id=j.scanner_id WHERE j.id='%JOB%'::uuid;"
if errorlevel 1 goto :dbfail
echo.

echo [2/6] Targets
docker exec rag_new2-postgres-1 psql -U forensic -d forensic -P pager=off -x -c ^
"SELECT target,target_type,credential_ref,excluded FROM %SCHEMA%.vuln_scan_targets WHERE scan_job_id='%JOB%'::uuid ORDER BY target;"
echo.

echo [3/6] Timeline for this scan job
docker exec rag_new2-postgres-1 psql -U forensic -d forensic -P pager=off -x -c ^
"SELECT timestamp_utc,event_type,actor,summary FROM %SCHEMA%.vuln_timeline_events WHERE source_id='%JOB%'::uuid ORDER BY timestamp_utc;"
echo.

echo [4/6] Scanner heartbeat / connection information
docker exec rag_new2-postgres-1 psql -U forensic -d forensic -P pager=off -x -c ^
"SELECT j.scanner_id,s.name,s.url,s.status,s.last_heartbeat_at,s.version,to_jsonb(s) AS scanner_json FROM %SCHEMA%.vuln_scan_jobs j LEFT JOIN %SCHEMA%.vuln_scanners s ON s.id=j.scanner_id WHERE j.id='%JOB%'::uuid;"
echo.

echo [5/6] Central logs around scanner activity
docker compose -f "%COMPOSE%" logs --since 30m --tail=500 api worker-nessus 2>&1 | findstr /I /C:"%JOB%" /C:"scanner-agent" /C:"OpenVAS" /C:"failed" /C:"error"
echo.

echo [6/6] Interpretation
echo.
echo If orchestration_json contains "edge_agent": true:
echo   The failure came from the laptop scanner agent. Run:
echo   Check-Failed-Scan-Laptop.cmd %JOB%
echo.
echo If error says "Scan config not found: Full and fast":
echo   Greenbone feed/config import is still not ready on the laptop.
echo.
echo If error says "No OpenVAS scanner found":
echo   Local gvmd scanner registration is missing.
echo.
echo If error mentions create_target/create_task/GMP/OSP:
echo   Paste this output and the laptop diagnostic output.
echo.
exit /b 0

:dbfail
echo.
echo [ERROR] Could not query %SCHEMA%.vuln_scan_jobs.
echo Verify PostgreSQL is healthy and that tenant schema is %SCHEMA%.
exit /b 1
