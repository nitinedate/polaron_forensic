@echo off
setlocal EnableExtensions EnableDelayedExpansion
cd /d "%~dp0"

set "JOB_ID=%~1"
if not defined JOB_ID set "JOB_ID=ddabfb92-3f2b-444b-8289-cf645dd21804"

set "TASK_ID=%~2"
if not defined TASK_ID set "TASK_ID=12143f78-afe0-4e37-8eb1-13cab3616c4e"

set "TARGET=%~3"
if not defined AETHERIS_LOG_SINCE (
  set "SINCE=6h"
) else (
  set "SINCE=%AETHERIS_LOG_SINCE%"
)

for /f "delims=" %%I in ('powershell -NoProfile -Command "Get-Date -Format yyyyMMdd-HHmmss"') do set "TS=%%I"
set "OUT=%CD%\diagnostics\future22-openvas-%TS%"
set "ZIP=%CD%\diagnostics\future22-openvas-%TS%.zip"
mkdir "%OUT%" >nul 2>&1
mkdir "%OUT%\logs" >nul 2>&1

echo ============================================================
echo Future 22 - OpenVAS Evidence Collector
echo Job : %JOB_ID%
echo Task: %TASK_ID%
echo Target: %TARGET%
echo ============================================================
echo READ-ONLY against Docker containers and Greenbone.
echo No stop, restart, recreate, remove, prune, or volume changes.
echo.

docker info >nul 2>&1
if errorlevel 1 (
  echo [ERROR] Docker Desktop is not running.
  exit /b 1
)

echo [1/8] Docker/Compose state
docker compose ps -a >"%OUT%\compose-ps-a.txt" 2>&1
docker stats --no-stream >"%OUT%\docker-stats.txt" 2>&1

echo [2/8] Scanner-agent runtime evidence
docker compose exec -T scanner-agent sh -c "echo ENV_AGENT_VERSION=$AGENT_VERSION; echo RUNTIME_AGENT_VERSION=$(cat /app/.agent-version 2>/dev/null || true); python --version; grep -n -E 'with conn:|GMP\(connection=|Etree(CheckCommand)?Transform|not claiming jobs' /app/agent/gmp_local.py /app/agent/main.py 2>/dev/null || true" >"%OUT%\scanner-agent-runtime.txt" 2>&1

echo [3/8] Direct GMP evidence for the OpenVAS task/report
>"%OUT%\gmp_task_probe.py" (
  echo import os
  echo from collections import Counter
  echo from lxml import etree
  echo from agent.gmp_local import LocalOpenVAS, _session
  echo.
  echo task_id = "%TASK_ID%"
  echo ov = LocalOpenVAS()
  echo print("TASK_ID=", task_id)
  echo print("SOCKET=", ov.socket_path)
  echo try:
  echo^    with _session(socket_path=ov.socket_path, host=ov.host, port=ov.port, username=ov.username, password=ov.password) as gmp:
  echo^        resp = gmp.get_task(task_id)
  echo^        tasks = resp.xpath(".//task") if hasattr(resp, "xpath") else []
  echo^        task = tasks[0] if tasks else resp.find("task")
  echo^        if task is None:
  echo^            print("TASK_FOUND=NO")
  echo^            raise SystemExit(20)
  echo^        print("TASK_FOUND=YES")
  echo^        print("TASK_NAME=", task.findtext("name"))
  echo^        print("TASK_STATUS=", task.findtext("status"))
  echo^        print("TASK_PROGRESS=", task.findtext("progress"))
  echo^        ids = []
  echo^        for xp in ("current_report/report", "last_report/report"):
  echo^            e = task.find(xp)
  echo^            if e is not None and e.get("id"):
  echo^                ids.append((xp, e.get("id")))
  echo^        print("REPORT_IDS=", ids)
  echo^        if not ids:
  echo^            print("REPORT_EVIDENCE=NO_REPORT_ID")
  echo^            print("TASK_XML=", etree.tostring(task, encoding="unicode")[:12000])
  echo^            raise SystemExit(21)
  echo^        report_id = ids[0][1]
  echo^        print("REPORT_ID_SELECTED=", report_id)
  echo^        rep = gmp.get_report(report_id=report_id, filter_string="rows=-1", ignore_pagination=True, details=True)
  echo^        results = rep.xpath(".//results/result")
  echo^        print("RAW_RESULT_COUNT=", len(results))
  echo^        hosts = []
  echo^        threats = Counter()
  echo^        severities = Counter()
  echo^        for r in results:
  echo^            h = (r.findtext("host") or "").strip()
  echo^            if h:
  echo^                hosts.append(h)
  echo^            threats[(r.findtext("threat") or "").strip().lower()] += 1
  echo^            severities[(r.findtext("severity") or "").strip()] += 1
  echo^        print("UNIQUE_RESULT_HOSTS=", sorted(set(hosts)))
  echo^        print("THREAT_COUNTS=", dict(threats))
  echo^        print("SEVERITY_VALUE_COUNTS=", dict(severities))
  echo^        host_nodes = rep.xpath(".//hosts/host")
  echo^        print("REPORT_HOST_NODE_COUNT=", len(host_nodes))
  echo^        print("REPORT_HOST_NODE_TEXT=", [((h.text or "").strip()) for h in host_nodes[:50]])
  echo^        for i, r in enumerate(results[:30], 1):
  echo^            nvt = r.find("nvt")
  echo^            print("RESULT", i, {
  echo^                "host": r.findtext("host"),
  echo^                "port": r.findtext("port"),
  echo^                "threat": r.findtext("threat"),
  echo^                "severity": r.findtext("severity"),
  echo^                "name": (nvt.findtext("name") if nvt is not None else r.findtext("name")),
  echo^                "oid": (nvt.get("oid") if nvt is not None else None),
  echo^            })
  echo^        print("REPORT_XML_PREFIX=", etree.tostring(rep, encoding="unicode")[:20000])
  echo except Exception as exc:
  echo^    print("PROBE_EXCEPTION=", repr(exc))
  echo^    raise
)

docker compose exec -T scanner-agent python - <"%OUT%\gmp_task_probe.py" >"%OUT%\openvas-task-report-evidence.txt" 2>&1
set "PROBE_RC=%ERRORLEVEL%"
echo Probe exit code: %PROBE_RC%
type "%OUT%\openvas-task-report-evidence.txt"
echo.

echo [4/8] Job-specific scanner-agent logs
docker compose logs --since "%SINCE%" --tail=5000 scanner-agent >"%OUT%\logs\scanner-agent.log" 2>&1
findstr /I /C:"%JOB_ID%" /C:"%TASK_ID%" /C:"completed with" /C:"Could not read results" /C:"Failed to start OpenVAS" "%OUT%\logs\scanner-agent.log" >"%OUT%\job-correlated-scanner-agent.txt" 2>&1
type "%OUT%\job-correlated-scanner-agent.txt"
echo.

echo [5/8] Greenbone daemon logs
docker compose logs --since "%SINCE%" --tail=5000 gvmd >"%OUT%\logs\gvmd.log" 2>&1
docker compose logs --since "%SINCE%" --tail=5000 ospd-openvas >"%OUT%\logs\ospd-openvas.log" 2>&1
findstr /I /C:"%TASK_ID%" /C:"edge-%JOB_ID:~0,8%" /C:"error" /C:"warning" "%OUT%\logs\gvmd.log" >"%OUT%\gvmd-correlated.txt" 2>&1
findstr /I /C:"%TASK_ID%" /C:"edge-%JOB_ID:~0,8%" /C:"error" /C:"warning" "%OUT%\logs\ospd-openvas.log" >"%OUT%\ospd-correlated.txt" 2>&1

echo [6/8] Greenbone readiness and scanner registration
docker compose exec -T scanner-agent python /app/check_greenbone_ready.py >"%OUT%\greenbone-readiness.txt" 2>&1
echo ExitCode=%ERRORLEVEL%>>"%OUT%\greenbone-readiness.txt"
docker compose exec -T -u gvmd gvmd gvmd --get-scanners >"%OUT%\gvmd-scanners.txt" 2>&1

echo [7/8] Optional target reachability from laptop
if defined TARGET (
  ping -n 4 "%TARGET%" >"%OUT%\target-ping.txt" 2>&1
  powershell -NoProfile -Command "$t='%TARGET%'; 22,53,80,135,139,443,445,3389 | ForEach-Object { $r=Test-NetConnection -ComputerName $t -Port $_ -WarningAction SilentlyContinue; [pscustomobject]@{Target=$t;Port=$_;Tcp=$r.TcpTestSucceeded;RemoteAddress=$r.RemoteAddress} } | Format-Table -AutoSize" >"%OUT%\target-common-ports.txt" 2>&1
) else (
  echo No target IP was supplied.>"%OUT%\target-reachability-not-run.txt"
)

echo [8/8] Create ZIP
(
  echo Job ID: %JOB_ID%
  echo OpenVAS Task ID: %TASK_ID%
  echo Target: %TARGET%
  echo Probe exit code: %PROBE_RC%
  echo.
  echo Read first:
  echo   openvas-task-report-evidence.txt
  echo   job-correlated-scanner-agent.txt
  echo   greenbone-readiness.txt
  echo   gvmd-correlated.txt
  echo   ospd-correlated.txt
)>"%OUT%\README-FIRST.txt"

powershell -NoProfile -Command "Compress-Archive -Path '%OUT%\*' -DestinationPath '%ZIP%' -Force" >"%OUT%\zip.log" 2>&1

echo.
echo ============================================================
echo COLLECTION COMPLETE
echo ============================================================
echo Folder: %OUT%
echo ZIP   : %ZIP%
echo.
echo Upload the ZIP to ChatGPT.
exit /b 0
