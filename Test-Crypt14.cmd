@echo off
powershell -NoProfile -ExecutionPolicy Bypass -File "%~dp0Test-Crypt14.ps1" %*
exit /b %ERRORLEVEL%
