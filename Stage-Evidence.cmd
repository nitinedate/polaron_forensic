@echo off
setlocal
cd /d "%~dp0"
if "%~2"=="" ( echo Usage: Stage-Evidence.cmd "G:\Image folder" case-name [-Verify] & exit /b 2 )
powershell -NoProfile -ExecutionPolicy Bypass -File "%~dp0scripts\stage-evidence.ps1" -Source "%~1" -CaseName "%~2" %3 %4
pause
