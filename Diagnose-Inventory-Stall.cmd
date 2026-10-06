@echo off
setlocal
cd /d "%~dp0"
if "%~1"=="" ( echo Usage: Diagnose-Inventory-Stall.cmd ^<job_id^> [firm_schema] & exit /b 2 )
docker compose cp diagnostics\diagnose_inventory_stall.py api:/tmp/diagnose_inventory_stall.py
docker compose exec -T api python /tmp/diagnose_inventory_stall.py %1 %2
pause
