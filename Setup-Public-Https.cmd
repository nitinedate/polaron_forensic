@echo off
REM Public HTTPS for this project. Run from any directory. Administrator PowerShell is required.
REM Example:
REM   Setup-Public-Https.cmd -SelfSigned -LanIP 192.168.1.9 -PublicIP 122.179.140.167 -ForceRecreate
setlocal
set "ROOT=%~dp0"
powershell -NoProfile -ExecutionPolicy Bypass -File "%ROOT%scripts\setup-public-https.ps1" %*
exit /b %ERRORLEVEL%
