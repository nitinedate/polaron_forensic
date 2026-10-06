@echo off
setlocal EnableExtensions
cd /d "%~dp0"
if not exist "%~dp0Apply-Scanner-v1.5.3.ps1" (
  echo ERROR: Extract Aetheris-Laptop-Scanner-v1.5.3.zip into this scanner folder first.
  pause
  exit /b 2
)
echo Applying Aetheris Laptop Scanner 1.5.3-v45.7...
powershell.exe -NoLogo -NoProfile -ExecutionPolicy Bypass -File "%~dp0Apply-Scanner-v1.5.3.ps1"
set "RC=%ERRORLEVEL%"
if not "%RC%"=="0" (
  echo Update failed with exit code %RC%.
  pause
  exit /b %RC%
)
echo Agent source and regression checks completed. Verify a live authorized scan on this host.
pause
exit /b 0
