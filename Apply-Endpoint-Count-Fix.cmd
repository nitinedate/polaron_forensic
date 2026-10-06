@echo off
setlocal EnableExtensions
cd /d "%~dp0"

echo ============================================================
echo Aetheris Gap Report Endpoint Count Fix - Deploy
echo ============================================================
echo Project: %CD%
echo.

if not exist "backend\app\services\gap_assessment_report.py" (
  echo [ERROR] Patched backend file was not found.
  exit /b 1
)

findstr /C:"def _derive_case_endpoint_count" "backend\app\services\gap_assessment_report.py" >nul 2>&1
if errorlevel 1 (
  echo [ERROR] The backend file does not contain the endpoint-count fix.
  exit /b 1
)

echo [OK] Patched backend source is present.

docker version >nul 2>&1
if errorlevel 1 (
  echo [ERROR] Docker Desktop engine is not reachable.
  exit /b 1
)

echo [OK] Docker engine is reachable.

set "COMPOSE_FILE=docker-compose.yml"
if exist "docker-compose.https.yml" set "COMPOSE_FILE=docker-compose.https.yml"

echo Using Compose file: %COMPOSE_FILE%

for /f "usebackq delims=" %%I in (`docker compose -f "%COMPOSE_FILE%" ps -q api 2^>nul`) do set "API_CONTAINER=%%I"

if not defined API_CONTAINER (
  echo [ERROR] Existing API container was not found.
  echo This script will not create or recreate containers.
  exit /b 1
)

echo API container: %API_CONTAINER%

rem The normal project uses ./backend:/app, so the host patch is already visible.
rem If a running API container does not see it, copy only this source file into
rem that same existing container. No container is removed or recreated.
docker exec "%API_CONTAINER%" sh -c "grep -q 'def _derive_case_endpoint_count' /app/app/services/gap_assessment_report.py" >nul 2>&1
if errorlevel 1 (
  echo Existing container does not yet see the patched source. Copying file...
  docker cp "backend\app\services\gap_assessment_report.py" "%API_CONTAINER%:/app/app/services/gap_assessment_report.py"
  if errorlevel 1 (
    echo [ERROR] Could not copy the patched backend file into the existing API container.
    exit /b 1
  )
)

echo [OK] Existing API container sees the patched source.

docker exec "%API_CONTAINER%" python -m py_compile /app/app/services/gap_assessment_report.py
if errorlevel 1 (
  echo [ERROR] Python syntax validation failed inside the API container.
  exit /b 1
)

echo [OK] Python syntax validation passed.

echo Restarting the SAME API container only...
docker restart "%API_CONTAINER%" >nul
if errorlevel 1 (
  echo [ERROR] API container restart failed.
  exit /b 1
)

echo [OK] API container restarted. No containers or volumes were deleted.

echo Waiting for API health...
set /a TRY=0
:health_loop
set /a TRY+=1
curl.exe -fsS http://127.0.0.1:8080/health >nul 2>&1
if not errorlevel 1 goto health_ok
if %TRY% GEQ 90 goto health_fail
timeout /t 2 /nobreak >nul
goto health_loop

:health_ok
echo [OK] API health returned successfully.
echo.
echo ============================================================
echo ENDPOINT COUNT FIX DEPLOYED
echo ============================================================
echo Regenerate the Gap Analysis PDF. If no manual endpoint count is saved,
echo the report now derives it from vuln_assets, then host-like scan targets.
echo.
echo No docker compose down, rm, --remove-orphans, prune, or volume deletion was used.
exit /b 0

:health_fail
echo [ERROR] API did not become healthy within the expected window.
echo Existing container was preserved. Check:
echo   docker logs --tail 200 %API_CONTAINER%
exit /b 1
