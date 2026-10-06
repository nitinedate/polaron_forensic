@echo off
setlocal
title Aetheris - model_run
cd /d "%~dp0.."

echo.
echo  Training the report model from the physical reports in
echo  backend\app\knowledge\document_report_model
echo  The report agents then use those queries and observation rules.
echo.

powershell -NoProfile -ExecutionPolicy Bypass -File "%~dp0model_run.ps1" %*
set ERR=%ERRORLEVEL%

echo.
if %ERR% neq 0 (
  echo  model_run failed with exit code %ERR%.
) else (
  echo  model_run finished.
)
echo.
pause
exit /b %ERR%
