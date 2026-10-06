@echo off
setlocal
title Aetheris - start_docker_nitin
cd /d "%~dp0.."
echo.
echo  Trusted HTTPS for the configured public IP and domain on ports 80/443.
echo  HTTPS gateway starts after certificate validation, before product stacks.
echo  Public TCP 80 and 443 must be forwarded to this Windows host.
echo  Application compiles every launch. Dependencies use Docker cache.
echo  First launch creates missing .env and host settings automatically.
echo  Host settings: script_docker\start_docker.settings.json
echo  Optional checks: -PrepareOnly or -ValidateOnly
echo  Optional maintenance: -RefreshDependencies
echo.
powershell.exe -NoProfile -ExecutionPolicy Bypass -File "%~dp0start_docker.ps1" -Profile nitin %*
set "ERR=%ERRORLEVEL%"
echo.
if %ERR% neq 0 (
  echo  Startup failed with exit code %ERR%.
) else (
  echo  Startup finished.
)
if not "%AETHERIS_NO_PAUSE%"=="1" pause
exit /b %ERR%
