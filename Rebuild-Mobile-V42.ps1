$ErrorActionPreference = "Stop"
Write-Host "Rebuilding Android mobile backend/workers and gateway/frontend for V42..." -ForegroundColor Cyan

docker compose -f services/mobile-android/docker-compose.yml --project-directory . build --no-cache api worker-build worker-parse worker-rag
docker compose -f services/mobile-android/docker-compose.yml --project-directory . up -d --force-recreate api worker-build worker-parse worker-rag

# Recreate the main gateway/frontend stack if present in the root compose.
docker compose build --no-cache gateway 2>$null
if ($LASTEXITCODE -eq 0) {
    docker compose up -d --force-recreate gateway
} else {
    Write-Host "Root compose has no buildable gateway service; rebuild your normal UI/gateway stack manually." -ForegroundColor Yellow
}

Write-Host "V42 rebuild complete. Restart the HostDrive helper/agent so the updated host-mobile-acquire.ps1 is loaded." -ForegroundColor Green
Write-Host "Then hard-refresh the browser once (Ctrl+F5)." -ForegroundColor Green
