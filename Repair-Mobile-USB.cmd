@echo off
setlocal
cd /d "%~dp0"
powershell.exe -NoProfile -ExecutionPolicy Bypass -File "%~dp0scripts\repair-mobile-usb.ps1"
set RC=%ERRORLEVEL%
echo.
if not "%RC%"=="0" echo Mobile USB repair finished with code %RC%.
pause
exit /b %RC%
