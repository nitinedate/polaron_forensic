$ErrorActionPreference = "Stop"
Set-Location $PSScriptRoot
Write-Host "Building scanner-agent test image..." -ForegroundColor Cyan
docker compose build --no-cache scanner-agent
Write-Host "Running scanner-agent unit/regression tests..." -ForegroundColor Cyan
docker compose run --rm --no-deps scanner-agent pytest -q
Write-Host "Scanner tests passed." -ForegroundColor Green
