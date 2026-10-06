@echo off
setlocal EnableExtensions

rem %~dp0 always ends with a backslash.  Do not pass that quoted trailing
rem backslash directly to powershell.exe because Windows native argument
rem parsing can turn the closing quote into a literal quote character.
set "ROOT=%~dp0"
for %%I in ("%ROOT%.") do set "ROOT=%%~fI"

cd /d "%ROOT%"
echo.
echo Repairing Greenbone feed import / Full-and-fast scan configuration (v1.4.3)...
echo Root: %ROOT%
echo.

powershell.exe -NoLogo -NoProfile -ExecutionPolicy Bypass -File "%ROOT%\scripts\Repair-Greenbone-Feed-v1.4.1.ps1" -Root "%ROOT%"
set "RC=%ERRORLEVEL%"

echo.
if "%RC%"=="0" (
  echo Greenbone repair completed successfully.
) else (
  echo Greenbone repair finished with exit code %RC%.
)
exit /b %RC%
