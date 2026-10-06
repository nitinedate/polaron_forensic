@echo off
setlocal
set "TARGET=%~1"
if "%TARGET%"=="" set "TARGET=%CD%"
if not exist "%TARGET%\scripts" mkdir "%TARGET%\scripts"
copy /Y "%~dp0scripts\Test-Aetheris-Central-TLS-v1.4.3.ps1" "%TARGET%\scripts\Test-Aetheris-Central-TLS-v1.4.3.ps1" >nul
copy /Y "%~dp0scripts\Repair-Aetheris-Central-TLS-v1.4.3.ps1" "%TARGET%\scripts\Repair-Aetheris-Central-TLS-v1.4.3.ps1" >nul
copy /Y "%~dp0scripts\Test-Central-TLS-Scripts-Parse-v1.4.3.ps1" "%TARGET%\scripts\Test-Central-TLS-Scripts-Parse-v1.4.3.ps1" >nul
echo [OK] v1.4.3 central TLS scripts copied to %TARGET%\scripts
endlocal
