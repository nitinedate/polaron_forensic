@echo off
setlocal EnableExtensions
cd /d F:\rag_new2
set "C=rag_new2-scap-data-1"

echo ============================================================
echo Aetheris - Non-destructive SCAP health repair
echo ============================================================
echo This script does NOT stop, remove, recreate, prune, or delete.
echo.

docker inspect %C% >nul 2>&1
if errorlevel 1 (
  echo [ERROR] Container %C% was not found.
  exit /b 1
)

echo [1/6] Current state
for /f "delims=" %%H in ('docker inspect %C% --format "{{if .State.Health}}{{.State.Health.Status}}{{else}}no-healthcheck{{end}}"') do set "HEALTH=%%H"
echo Health: %HEALTH%
docker inspect %C% --format "Healthcheck: {{json .Config.Healthcheck.Test}}"
echo.

echo [2/6] Verify copied SCAP feed files
docker exec %C% sh -c "test -e /mnt/feed.xml && test -e /mnt/timestamp && echo SCAP_DATA_OK || (echo SCAP_DATA_MISSING; exit 2)"
if errorlevel 1 (
  echo [ERROR] SCAP feed metadata is missing. No marker will be changed.
  echo Recent container logs:
  docker logs --tail 120 %C%
  exit /b 2
)
echo.

echo [3/6] Inspect image health state marker
docker exec %C% sh -c "echo STATE_FILE=$STATE_FILE; if test -n \"$STATE_FILE\"; then ls -ld $(dirname $STATE_FILE) 2>/dev/null || true; ls -l $STATE_FILE 2>/dev/null || true; fi"
echo.

echo [4/6] Repair missing state marker only after feed verification
docker exec %C% sh -c "if test -n \"$STATE_FILE\"; then mkdir -p $(dirname $STATE_FILE) && touch $STATE_FILE && echo MARKER_OK:$STATE_FILE; else echo NO_STATE_FILE_DEFINED; fi"
if errorlevel 1 (
  echo [ERROR] Could not repair the health marker.
  exit /b 3
)
echo.

echo [5/6] Wait for Docker healthcheck to run
timeout /t 20 /nobreak >nul
for /f "delims=" %%H in ('docker inspect %C% --format "{{if .State.Health}}{{.State.Health.Status}}{{else}}no-healthcheck{{end}}"') do set "HEALTH=%%H"
echo Health after repair: %HEALTH%
echo.

if /I "%HEALTH%"=="healthy" goto :success

echo [6/6] Still unhealthy - printing exact Docker health failures
docker inspect %C% --format "{{range .State.Health.Log}}{{println .End \"exit=\" .ExitCode .Output}}{{end}}"
echo.
echo [INFO] SCAP data copy is present, but the image healthcheck is still failing.
echo Paste the output above back into ChatGPT for the exact next fix.
exit /b 4

:success
echo [6/6] SUCCESS

echo SCAP container is healthy.
echo No containers or volumes were deleted or recreated.
echo.
docker compose -f docker-compose.https.yml --profile gvm ps scap-data cert-bund-data dfn-cert-data
exit /b 0
