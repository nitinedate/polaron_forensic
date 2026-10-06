@echo off
powershell.exe -NoProfile -ExecutionPolicy Bypass -File "%~dp0Test-Crypt.ps1" %*
exit /b %errorlevel%
