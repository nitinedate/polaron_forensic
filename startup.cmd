@echo off
setlocal EnableExtensions
title Aetheris - Sequential stack startup
cd /d "%~dp0"

echo.
echo  ============================================================
echo   Aetheris sequential Docker startup
echo  ------------------------------------------------------------
echo   Starts each compose service one by one.
echo   Already-running services are left alone.
echo   One-shot jobs (init/migrator/config) that already finished
echo   are ignored -- they are meant to exit after one run.
echo   After the stack is ready, scanner test cases are executed
echo   and a pass/fail summary is printed.
echo.
echo   Options (passed through):
echo     -SkipTests       Start containers only
echo     -Build           Force image rebuild before starting
echo     -IncludeWazuh    Also start the wazuh profile
echo     -SkipHealthWait  Do not wait for healthy/HTTP
echo  ============================================================
echo.

powershell -NoProfile -ExecutionPolicy Bypass -File "%~dp0scripts\startup.ps1" %*
set ERR=%ERRORLEVEL%

echo.
if %ERR% equ 0 (
  echo  Startup finished. Stack is up and scanner tests passed.
) else if %ERR% equ 2 (
  echo  Stack is up, but one or more scanner tests FAILED. See the summary above.
) else (
  echo  Startup failed with exit code %ERR%.
)
echo.
pause
exit /b %ERR%
