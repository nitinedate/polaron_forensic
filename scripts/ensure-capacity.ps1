# Ensure the shared Redis (services/common) is up.
# Product workers use redis://redis:6379/15 for CPU/GPU semaphore leases.
# Host tools can use redis://127.0.0.1:6380/15.
#
# Usage (from repo root):
#   powershell -NoProfile -ExecutionPolicy Bypass -File scripts\ensure-capacity.ps1

param(
    [int]$WaitTimeoutSec = 180
)

$ErrorActionPreference = "Stop"
$root = Split-Path -Parent (Split-Path -Parent $MyInvocation.MyCommand.Path)

function Resolve-Docker {
    $cmd = Get-Command docker -ErrorAction SilentlyContinue
    if ($cmd) { return $cmd.Source }
    $fallback = "C:\Program Files\Docker\Docker\resources\bin\docker.exe"
    if (Test-Path $fallback) { return $fallback }
    throw "Docker not found."
}

$docker = Resolve-Docker
Write-Host "Ensuring shared infrastructure (Postgres, Redis, MinIO, pgAdmin, MailHog)..." -ForegroundColor Cyan
& $docker compose --project-directory $root --project-name aetheris-common `
    -f services/common/docker-compose.yml up -d --wait --wait-timeout $WaitTimeoutSec postgres redis minio pgadmin mailhog
if ($LASTEXITCODE -ne 0) {
    throw "aetheris-common startup failed (exit $LASTEXITCODE)"
}
Write-Host "Shared Redis is healthy on 127.0.0.1:6380 (leases use logical database 15)." -ForegroundColor Green
