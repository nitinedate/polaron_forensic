$ErrorActionPreference = "Stop"
Set-Location $PSScriptRoot

Write-Host "[1/3] Building frontend without cache..." -ForegroundColor Cyan
docker compose build --no-cache frontend

Write-Host "[2/3] Recreating frontend container..." -ForegroundColor Cyan
docker compose up -d --force-recreate frontend

Write-Host "[3/3] Frontend status..." -ForegroundColor Cyan
docker compose ps frontend

Write-Host "V30.3 frontend is running. Hard-refresh the browser with Ctrl+F5." -ForegroundColor Green
