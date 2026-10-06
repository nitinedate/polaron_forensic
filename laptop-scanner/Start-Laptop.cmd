@echo off
setlocal EnableExtensions

rem Prefer the durable install. Opening this .cmd from inside a .zip uses a Temp
rem extract path that disappears and breaks -File lookups.
set "ROOT=%~dp0"
if exist "%ROOT%scripts\start-laptop.ps1" goto :run
if exist "D:\laptop-scanner\scripts\start-laptop.ps1" (
  set "ROOT=D:\laptop-scanner\"
  goto :run
)

echo.
echo ERROR: Could not find scripts\start-laptop.ps1 next to this launcher.
echo Do not run Start-Laptop.cmd from inside a .zip / Temp extract.
echo Run the installed copy instead:
echo   D:\laptop-scanner\Start-Laptop.cmd
echo.
pause
exit /b 1

:run
cd /d "%ROOT%"
echo Starting Aetheris laptop scanner stack...
echo  (Docker Desktop, Local OpenVAS, Scanner Agent)
echo.
echo Root: %CD%
echo.
powershell.exe -NoLogo -NoProfile -ExecutionPolicy Bypass -File "%ROOT%scripts\start-laptop.ps1"
set "RC=%ERRORLEVEL%"
if not "%RC%"=="0" (
  echo.
  echo Startup failed with exit code %RC%.
  echo.
  pause
  exit /b %RC%
)
echo.
echo Startup completed successfully.
echo.
pause
exit /b 0
