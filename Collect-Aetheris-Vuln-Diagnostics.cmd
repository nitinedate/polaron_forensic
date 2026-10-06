@echo off
setlocal EnableExtensions EnableDelayedExpansion
cd /d "%~dp0"

rem ============================================================
rem Aetheris Vulnerability Diagnostics Collector
rem READ-ONLY: no stop/restart/down/rm/prune/recreate/volume changes
rem
rem CENTRAL:
rem   Collect-Aetheris-Vuln-Diagnostics.cmd central "future 22"
rem
rem LAPTOP:
rem   Collect-Aetheris-Vuln-Diagnostics.cmd laptop <job-id> [target-ip]
rem
rem Optional:
rem   set AETHERIS_LOG_SINCE=48h
rem ============================================================

set "MODE=%~1"
if not defined MODE (
  if exist "docker-compose.https.yml" set "MODE=central"
  if exist "scanner-agent\agent\main.py" set "MODE=laptop"
)

if /I not "%MODE%"=="central" if /I not "%MODE%"=="laptop" (
  echo Usage:
  echo   Central: %~nx0 central "future 22"
  echo   Laptop : %~nx0 laptop JOB-UUID [TARGET-IP]
  exit /b 1
)

if not defined AETHERIS_LOG_SINCE (
  set "SINCE=24h"
) else (
  set "SINCE=%AETHERIS_LOG_SINCE%"
)

for /f "delims=" %%I in ('powershell -NoProfile -Command "Get-Date -Format yyyyMMdd-HHmmss"') do set "TS=%%I"
if not defined TS set "TS=diagnostic"

docker info >nul 2>&1
if errorlevel 1 (
  echo [ERROR] Docker engine is not available.
  exit /b 2
)

if /I "%MODE%"=="central" goto :CENTRAL
goto :LAPTOP


:CENTRAL
set "CASE_TITLE=%~2"
if not defined CASE_TITLE set "CASE_TITLE=future 22"
set "COMPOSE=docker-compose.https.yml"
set "SCHEMA=firm_aetheris"
set "SAFECASE=%CASE_TITLE: =_%"
set "OUT=%CD%\diagnostics\central-%SAFECASE%-%TS%"
set "ZIP=%CD%\diagnostics\central-%SAFECASE%-%TS%.zip"
mkdir "%OUT%" >nul 2>&1
mkdir "%OUT%\db" >nul 2>&1
mkdir "%OUT%\logs" >nul 2>&1
mkdir "%OUT%\inspect" >nul 2>&1

echo ============================================================
echo Aetheris CENTRAL vulnerability diagnostics
echo Case: %CASE_TITLE%
echo Logs: %SINCE%
echo Output: %OUT%
echo ============================================================
echo READ-ONLY: no containers or volumes will be modified.
echo.

echo [1/10] Capture Docker/Compose state
docker version >"%OUT%\docker-version.txt" 2>&1
docker compose version >"%OUT%\compose-version.txt" 2>&1
docker compose -f "%COMPOSE%" --profile gvm --profile vuln-scanners ps -a >"%OUT%\compose-ps-a.txt" 2>&1
docker ps -a --filter "name=rag_new2-" --format "table {{.Names}}\t{{.Image}}\t{{.Status}}\t{{.Ports}}" >"%OUT%\docker-ps-project.txt" 2>&1
docker stats --no-stream >"%OUT%\docker-stats.txt" 2>&1
docker system df >"%OUT%\docker-system-df.txt" 2>&1
docker compose -f "%COMPOSE%" --profile gvm --profile vuln-scanners config --services >"%OUT%\compose-services.txt" 2>&1
docker compose -f "%COMPOSE%" --profile gvm --profile vuln-scanners config --images >"%OUT%\compose-images.txt" 2>&1

for /f "delims=" %%N in ('docker ps -a --filter "name=rag_new2-" --format "{{.Names}}"') do (
  docker inspect "%%N" --format "Name={{.Name}} Image={{.Config.Image}} Status={{.State.Status}} Running={{.State.Running}} Restarting={{.State.Restarting}} OOMKilled={{.State.OOMKilled}} ExitCode={{.State.ExitCode}} RestartCount={{.RestartCount}} StartedAt={{.State.StartedAt}} FinishedAt={{.State.FinishedAt}} Health={{if .State.Health}}{{.State.Health.Status}}{{else}}none{{end}} Networks={{json .NetworkSettings.Networks}}" >"%OUT%\inspect\%%N.txt" 2>&1
  docker inspect "%%N" --format "{{if .State.Health}}{{range .State.Health.Log}}{{println .End \"exit=\" .ExitCode .Output}}{{end}}{{end}}" >>"%OUT%\inspect\%%N.txt" 2>&1
)

echo [2/10] Locate PostgreSQL and case
set "PGID="
for /f "delims=" %%C in ('docker compose -f "%COMPOSE%" ps -q postgres 2^>nul') do if not defined PGID set "PGID=%%C"
if not defined PGID (
  for /f "delims=" %%C in ('docker ps -q --filter "name=rag_new2-postgres-1"') do if not defined PGID set "PGID=%%C"
)
if not defined PGID (
  echo [ERROR] PostgreSQL container not found.>"%OUT%\FATAL.txt"
  goto :CENTRAL_LOGS
)

docker exec "%PGID%" psql -U forensic -d forensic -P pager=off -c "SELECT id,title,created_at FROM %SCHEMA%.cases WHERE lower(title) LIKE lower('%%%CASE_TITLE%%%') ORDER BY created_at DESC;" >"%OUT%\db\case-candidates.txt" 2>&1

set "CASE_ID="
for /f "usebackq delims=" %%I in (`docker exec "%PGID%" psql -U forensic -d forensic -Atc "SELECT id FROM %SCHEMA%.cases WHERE lower(title)=lower('%CASE_TITLE%') ORDER BY created_at DESC LIMIT 1;" 2^>nul`) do if not defined CASE_ID set "CASE_ID=%%I"
if not defined CASE_ID (
  for /f "usebackq delims=" %%I in (`docker exec "%PGID%" psql -U forensic -d forensic -Atc "SELECT id FROM %SCHEMA%.cases WHERE lower(title) LIKE lower('%%%CASE_TITLE%%%') ORDER BY created_at DESC LIMIT 1;" 2^>nul`) do if not defined CASE_ID set "CASE_ID=%%I"
)
if not defined CASE_ID (
  echo [ERROR] Could not resolve case "%CASE_TITLE%".>"%OUT%\db\VERDICT.txt"
  goto :CENTRAL_LOGS
)

echo %CASE_ID%>"%OUT%\db\CASE_ID.txt"
echo [OK] Case ID: %CASE_ID%

echo [3/10] Resolve latest scan job
set "JOB_ID="
for /f "usebackq delims=" %%I in (`docker exec "%PGID%" psql -U forensic -d forensic -Atc "SELECT id FROM %SCHEMA%.vuln_scan_jobs WHERE case_id='%CASE_ID%'::uuid ORDER BY created_at DESC LIMIT 1;" 2^>nul`) do if not defined JOB_ID set "JOB_ID=%%I"
if defined JOB_ID (
  echo %JOB_ID%>"%OUT%\db\LATEST_JOB_ID.txt"
  echo [OK] Latest job: %JOB_ID%
) else (
  echo NONE>"%OUT%\db\LATEST_JOB_ID.txt"
  echo [WARN] No scan job exists for this case.
)

echo [4/10] Produce verification verdict
if not defined JOB_ID (
  (
    echo Case: %CASE_TITLE%
    echo Case ID: %CASE_ID%
    echo Verdict: UNVERIFIED - NO SCAN JOB EXISTS
  )>"%OUT%\db\VERDICT.txt"
) else (
  docker exec "%PGID%" psql -U forensic -d forensic -P pager=off -x -c "WITH latest AS (SELECT * FROM %SCHEMA%.vuln_scan_jobs WHERE id='%JOB_ID%'::uuid), tgt AS (SELECT COUNT(*) FILTER (WHERE NOT excluded)::int AS targets FROM %SCHEMA%.vuln_scan_targets WHERE scan_job_id='%JOB_ID%'::uuid), res AS (SELECT COUNT(*)::int AS result_rows, COALESCE(MAX(hosts_attempted),0)::int AS hosts_attempted, COALESCE(MAX(hosts_assessed),0)::int AS hosts_assessed, COALESCE(MAX(plugin_error_count),0)::int AS plugin_errors FROM %SCHEMA%.vuln_scan_results WHERE scan_job_id='%JOB_ID%'::uuid), f AS (SELECT COUNT(*)::int AS total_findings, COUNT(*) FILTER (WHERE status='open')::int AS open_findings, COUNT(*) FILTER (WHERE status='open' AND lower(COALESCE(severity,'')) NOT IN ('info','informational'))::int AS actionable_open FROM %SCHEMA%.vuln_findings WHERE scan_job_id='%JOB_ID%'::uuid) SELECT l.id AS scan_job_id,l.status,l.started_at,l.completed_at,l.external_scan_id,l.error,l.orchestration_json,tgt.targets,res.result_rows,res.hosts_attempted,res.hosts_assessed,res.plugin_errors,f.total_findings,f.open_findings,f.actionable_open,CASE WHEN l.status IN ('failed','cancelled','canceled') THEN 'INVALID - SCAN DID NOT COMPLETE' WHEN l.status NOT IN ('completed') THEN 'UNVERIFIED - SCAN NOT COMPLETE' WHEN l.external_scan_id IS NULL THEN 'UNVERIFIED - COMPLETED BUT NO OPENVAS TASK ID' WHEN COALESCE((l.orchestration_json->>'partial')::boolean,false) THEN 'UNVERIFIED - PARTIAL SCAN' WHEN l.error IS NOT NULL AND btrim(l.error)<>'' THEN 'UNVERIFIED - COMPLETED WITH ERROR/PARTIAL NOTE' WHEN res.result_rows=0 THEN 'UNVERIFIED - NO DURABLE vuln_scan_results EVIDENCE ROW' WHEN res.hosts_assessed < tgt.targets THEN 'UNVERIFIED - NOT ALL TARGETS ASSESSED' WHEN f.total_findings=0 THEN 'VERIFIED CLEAN - COMPLETED, EVIDENCED, ZERO FINDINGS' ELSE 'COMPLETED - FINDINGS PRESENT' END AS verification_verdict FROM latest l CROSS JOIN tgt CROSS JOIN res CROSS JOIN f;" >"%OUT%\db\VERDICT.txt" 2>&1
)

echo [5/10] Export case/scan evidence from PostgreSQL
docker exec "%PGID%" psql -U forensic -d forensic -P pager=off -x -c "SELECT jsonb_pretty(to_jsonb(c)) FROM %SCHEMA%.cases c WHERE id='%CASE_ID%'::uuid;" >"%OUT%\db\case.json.txt" 2>&1
docker exec "%PGID%" psql -U forensic -d forensic -P pager=off -x -c "SELECT jsonb_pretty(to_jsonb(j)) FROM %SCHEMA%.vuln_scan_jobs j WHERE case_id='%CASE_ID%'::uuid ORDER BY created_at;" >"%OUT%\db\scan-jobs.json.txt" 2>&1
docker exec "%PGID%" psql -U forensic -d forensic -P pager=off -x -c "SELECT jsonb_pretty(to_jsonb(t)) FROM %SCHEMA%.vuln_scan_targets t WHERE scan_job_id IN (SELECT id FROM %SCHEMA%.vuln_scan_jobs WHERE case_id='%CASE_ID%'::uuid);" >"%OUT%\db\scan-targets.json.txt" 2>&1
docker exec "%PGID%" psql -U forensic -d forensic -P pager=off -x -c "SELECT jsonb_pretty(to_jsonb(r)) FROM %SCHEMA%.vuln_scan_results r WHERE scan_job_id IN (SELECT id FROM %SCHEMA%.vuln_scan_jobs WHERE case_id='%CASE_ID%'::uuid);" >"%OUT%\db\scan-results.json.txt" 2>&1
docker exec "%PGID%" psql -U forensic -d forensic -P pager=off -x -c "SELECT jsonb_pretty(to_jsonb(f)) FROM %SCHEMA%.vuln_findings f WHERE case_id='%CASE_ID%'::uuid;" >"%OUT%\db\findings.json.txt" 2>&1
docker exec "%PGID%" psql -U forensic -d forensic -P pager=off -x -c "SELECT status,severity,COUNT(*) AS n FROM %SCHEMA%.vuln_findings WHERE case_id='%CASE_ID%'::uuid GROUP BY status,severity ORDER BY status,severity;" >"%OUT%\db\findings-summary.txt" 2>&1
docker exec "%PGID%" psql -U forensic -d forensic -P pager=off -x -c "SELECT jsonb_pretty(to_jsonb(a)) FROM %SCHEMA%.vuln_assets a WHERE case_id='%CASE_ID%'::uuid;" >"%OUT%\db\assets.json.txt" 2>&1
docker exec "%PGID%" psql -U forensic -d forensic -P pager=off -x -c "SELECT jsonb_pretty(to_jsonb(e)) FROM %SCHEMA%.vuln_timeline_events e WHERE source_id='%CASE_ID%'::uuid OR source_id IN (SELECT id FROM %SCHEMA%.vuln_scan_jobs WHERE case_id='%CASE_ID%'::uuid) ORDER BY timestamp_utc;" >"%OUT%\db\timeline.json.txt" 2>&1
docker exec "%PGID%" psql -U forensic -d forensic -P pager=off -x -c "SELECT jsonb_pretty(to_jsonb(s)) FROM %SCHEMA%.vuln_scanners s WHERE id IN (SELECT scanner_id FROM %SCHEMA%.vuln_scan_jobs WHERE case_id='%CASE_ID%'::uuid AND scanner_id IS NOT NULL);" >"%OUT%\db\scanners.json.txt" 2>&1
docker exec "%PGID%" psql -U forensic -d forensic -P pager=off -c "SELECT table_name,column_name,data_type FROM information_schema.columns WHERE table_schema='%SCHEMA%' AND table_name LIKE 'vuln_%%' ORDER BY table_name,ordinal_position;" >"%OUT%\db\vuln-schema-columns.txt" 2>&1

if defined JOB_ID (
  docker exec "%PGID%" psql -U forensic -d forensic -Atc "SELECT target FROM %SCHEMA%.vuln_scan_targets WHERE scan_job_id='%JOB_ID%'::uuid AND NOT excluded ORDER BY target;" >"%OUT%\db\LATEST_TARGETS.txt" 2>&1
)

:CENTRAL_LOGS
echo [6/10] Collect ALL rag_new2 container logs for %SINCE%
for /f "delims=" %%N in ('docker ps -a --filter "name=rag_new2-" --format "{{.Names}}"') do (
  echo   collecting %%N
  docker logs --since "%SINCE%" --timestamps "%%N" >"%OUT%\logs\%%N.log" 2>&1
)

echo [7/10] Build job-correlated log extract
if defined JOB_ID (
  >"%OUT%\job-correlated-central.txt" (
    for %%F in ("%OUT%\logs\*.log") do (
      findstr /I /C:"%JOB_ID%" "%%~fF" 2>nul
    )
  )
) else (
  echo No job ID resolved.>"%OUT%\job-correlated-central.txt"
)

echo [8/10] Capture public/local API reachability
curl.exe -sS -k -D "%OUT%\local-api-headers.txt" "http://127.0.0.1:8080/health" >"%OUT%\local-api-health.txt" 2>"%OUT%\local-api-error.txt"
curl.exe -sS -k -D "%OUT%\public-api-headers.txt" "https://122.170.114.36/api/health" >"%OUT%\public-api-health.txt" 2>"%OUT%\public-api-error.txt"

echo [9/10] Write operator summary
(
  echo Mode: CENTRAL
  echo Case title: %CASE_TITLE%
  echo Case ID: %CASE_ID%
  echo Latest job ID: %JOB_ID%
  echo Log window: %SINCE%
  echo.
  echo Read db\VERDICT.txt first.
  echo If the scan uses edge_agent, run this SAME CMD on the scanner laptop:
  echo   Collect-Aetheris-Vuln-Diagnostics.cmd laptop %JOB_ID% TARGET-IP
  echo.
  echo TARGET-IP is listed in db\LATEST_TARGETS.txt
)>"%OUT%\README-FIRST.txt"

echo [10/10] Create ZIP
powershell -NoProfile -Command "Compress-Archive -Path '%OUT%\*' -DestinationPath '%ZIP%' -Force" >"%OUT%\zip.log" 2>&1
if exist "%ZIP%" (
  echo.
  echo ============================================================
  echo CENTRAL DIAGNOSTICS COMPLETE
  echo ============================================================
  echo Verdict:
  type "%OUT%\db\VERDICT.txt"
  echo.
  echo ZIP: %ZIP%
  echo Latest job: %JOB_ID%
  if exist "%OUT%\db\LATEST_TARGETS.txt" (
    echo Targets:
    type "%OUT%\db\LATEST_TARGETS.txt"
  )
  echo.
  echo Upload the ZIP to ChatGPT for analysis.
  exit /b 0
)
echo [WARN] ZIP creation failed. Folder is still available:
echo %OUT%
exit /b 3


:LAPTOP
set "JOB_ID=%~2"
set "TARGET=%~3"
set "OUT=%CD%\diagnostics\laptop-%TS%"
set "ZIP=%CD%\diagnostics\laptop-%TS%.zip"
mkdir "%OUT%" >nul 2>&1
mkdir "%OUT%\logs" >nul 2>&1
mkdir "%OUT%\inspect" >nul 2>&1

echo ============================================================
echo Aetheris LAPTOP scanner diagnostics
echo Job: %JOB_ID%
echo Target: %TARGET%
echo Logs: %SINCE%
echo Output: %OUT%
echo ============================================================
echo READ-ONLY: no containers or volumes will be modified.
echo.

echo [1/9] Capture Docker/Compose state
docker version >"%OUT%\docker-version.txt" 2>&1
docker compose version >"%OUT%\compose-version.txt" 2>&1
docker compose ps -a >"%OUT%\compose-ps-a.txt" 2>&1
docker stats --no-stream >"%OUT%\docker-stats.txt" 2>&1
docker compose config --services >"%OUT%\compose-services.txt" 2>&1
docker compose config --images >"%OUT%\compose-images.txt" 2>&1

for /f "delims=" %%C in ('docker compose ps -aq 2^>nul') do (
  for /f "delims=" %%N in ('docker inspect "%%C" --format "{{.Name}}"') do (
    set "N=%%N"
    set "N=!N:/=!"
    docker inspect "%%C" --format "Name={{.Name}} Image={{.Config.Image}} Status={{.State.Status}} Running={{.State.Running}} Restarting={{.State.Restarting}} OOMKilled={{.State.OOMKilled}} ExitCode={{.State.ExitCode}} RestartCount={{.RestartCount}} StartedAt={{.State.StartedAt}} FinishedAt={{.State.FinishedAt}} Health={{if .State.Health}}{{.State.Health.Status}}{{else}}none{{end}} Networks={{json .NetworkSettings.Networks}}" >"%OUT%\inspect\!N!.txt" 2>&1
    docker inspect "%%C" --format "{{if .State.Health}}{{range .State.Health.Log}}{{println .End \"exit=\" .ExitCode .Output}}{{end}}{{end}}" >>"%OUT%\inspect\!N!.txt" 2>&1
  )
)

echo [2/9] Collect ALL laptop compose-container logs for %SINCE%
for /f "delims=" %%C in ('docker compose ps -aq 2^>nul') do (
  for /f "delims=" %%N in ('docker inspect "%%C" --format "{{.Name}}"') do (
    set "N=%%N"
    set "N=!N:/=!"
    echo   collecting !N!
    docker logs --since "%SINCE%" --timestamps "%%C" >"%OUT%\logs\!N!.log" 2>&1
  )
)

echo [3/9] Scanner-agent runtime version and source signatures
docker compose exec -T scanner-agent sh -c "echo ENV_AGENT_VERSION=$AGENT_VERSION; echo RUNTIME_VERSION_FILE=$(cat /app/.agent-version 2>/dev/null || true); echo TOKEN_FILE_PRESENT=$(test -s /app/.agent-token && echo yes || echo no); python --version; python -c 'import gvm; print(\"python-gvm\", getattr(gvm,\"__version__\",\"unknown\"))' 2>/dev/null || true; grep -n -E 'with conn:|GMP\\(connection=|Etree(CheckCommand)?Transform|not claiming jobs' /app/agent/gmp_local.py /app/agent/main.py 2>/dev/null || true" >"%OUT%\scanner-agent-runtime.txt" 2>&1

echo [4/9] Greenbone readiness and sockets
docker compose exec -T scanner-agent python /app/check_greenbone_ready.py >"%OUT%\greenbone-readiness.txt" 2>&1
echo ExitCode=%ERRORLEVEL%>>"%OUT%\greenbone-readiness.txt"
docker compose exec -T gvmd sh -c "id; ls -la /run/gvmd /run/ospd 2>/dev/null; test -S /run/gvmd/gvmd.sock && echo GMP_SOCKET_OK || echo GMP_SOCKET_MISSING; test -S /run/ospd/ospd-openvas.sock && echo OSP_SOCKET_OK || echo OSP_SOCKET_MISSING" >"%OUT%\greenbone-sockets.txt" 2>&1
docker compose exec -T -u gvmd gvmd gvmd --get-scanners >"%OUT%\gvmd-scanners.txt" 2>&1
docker compose exec -T -u gvmd gvmd gvmd --get-users --verbose >"%OUT%\gvmd-users.txt" 2>&1

echo [5/9] Job-correlated scanner logs
if defined JOB_ID (
  >"%OUT%\job-correlated-laptop.txt" (
    for %%F in ("%OUT%\logs\*.log") do (
      findstr /I /C:"%JOB_ID%" /C:"edge-%JOB_ID:~0,8%" "%%~fF" 2>nul
    )
  )
) else (
  echo No job ID supplied.>"%OUT%\job-correlated-laptop.txt"
)

echo [6/9] Central HTTPS connectivity from laptop
curl.exe -sS -k -D "%OUT%\central-health-headers.txt" "https://122.170.114.36/api/health" >"%OUT%\central-health.txt" 2>"%OUT%\central-health-error.txt"

echo [7/9] Optional target network evidence
if defined TARGET (
  ping -n 3 "%TARGET%" >"%OUT%\target-ping.txt" 2>&1
  powershell -NoProfile -Command "$t='%TARGET%'; 22,80,135,139,443,445,3389 | ForEach-Object { $r=Test-NetConnection -ComputerName $t -Port $_ -WarningAction SilentlyContinue; [pscustomobject]@{Target=$t;Port=$_;TcpTestSucceeded=$r.TcpTestSucceeded;RemoteAddress=$r.RemoteAddress} } | Format-Table -AutoSize" >"%OUT%\target-common-ports.txt" 2>&1
) else (
  echo No target supplied.>"%OUT%\target-network.txt"
)

echo [8/9] Write operator summary
(
  echo Mode: LAPTOP
  echo Job ID: %JOB_ID%
  echo Target: %TARGET%
  echo Log window: %SINCE%
  echo.
  echo Read these first:
  echo   greenbone-readiness.txt
  echo   scanner-agent-runtime.txt
  echo   job-correlated-laptop.txt
  echo   logs\*scanner-agent*.log
  echo   logs\*gvmd*.log
  echo   logs\*ospd-openvas*.log
)>"%OUT%\README-FIRST.txt"

echo [9/9] Create ZIP
powershell -NoProfile -Command "Compress-Archive -Path '%OUT%\*' -DestinationPath '%ZIP%' -Force" >"%OUT%\zip.log" 2>&1
if exist "%ZIP%" (
  echo.
  echo ============================================================
  echo LAPTOP DIAGNOSTICS COMPLETE
  echo ============================================================
  echo Greenbone readiness:
  type "%OUT%\greenbone-readiness.txt"
  echo.
  echo ZIP: %ZIP%
  echo Upload the ZIP to ChatGPT together with the CENTRAL ZIP.
  exit /b 0
)
echo [WARN] ZIP creation failed. Folder is still available:
echo %OUT%
exit /b 4
