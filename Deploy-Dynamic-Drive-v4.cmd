@echo off
setlocal
powershell.exe -NoProfile -ExecutionPolicy Bypass -File "%~dp0scripts\deploy-dynamic-drive-v4.ps1" %*
exit /b %ERRORLEVEL%
