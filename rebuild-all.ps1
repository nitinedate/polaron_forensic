$ErrorActionPreference = "Stop"

Write-Host ""
Write-Host "========================================="
Write-Host " POLARON - FULL DOCKER REBUILD"
Write-Host "========================================="
Write-Host ""

# ---------------------------------------------------------
# 1. Detect Docker Compose file
# ---------------------------------------------------------

$ComposeFile = $null

$Candidates = @(
    "docker-compose.yml",
    "docker-compose.yaml",
    "compose.yml",
    "compose.yaml"
)

foreach ($file in $Candidates) {
    if (Test-Path $file) {
        $ComposeFile = $file
        break
    }
}

if (-not $ComposeFile) {
    Write-Host "ERROR: Docker Compose file not found."
    Write-Host "Expected one of:"
    Write-Host "  docker-compose.yml"
    Write-Host "  docker-compose.yaml"
    Write-Host "  compose.yml"
    Write-Host "  compose.yaml"
    exit 1
}

Write-Host "Using compose file: $ComposeFile"
Write-Host ""


# ---------------------------------------------------------
# 2. Verify Docker
# ---------------------------------------------------------

Write-Host "[1/10] Checking Docker..."

docker version

if ($LASTEXITCODE -ne 0) {
    Write-Host ""
    Write-Host "ERROR: Docker is not running."
    Write-Host "Start Docker Desktop and run this script again."
    exit 1
}

docker compose version

if ($LASTEXITCODE -ne 0) {
    Write-Host ""
    Write-Host "ERROR: Docker Compose is unavailable."
    exit 1
}


# ---------------------------------------------------------
# 3. Show current containers
# ---------------------------------------------------------

Write-Host ""
Write-Host "[2/10] Current Docker Compose status..."

docker compose -f $ComposeFile ps


# ---------------------------------------------------------
# 4. Stop existing stack
# ---------------------------------------------------------

Write-Host ""
Write-Host "[3/10] Stopping existing stack..."

docker compose -f $ComposeFile down --remove-orphans


# ---------------------------------------------------------
# 5. Remove compose-created containers if any remain
# ---------------------------------------------------------

Write-Host ""
Write-Host "[4/10] Removing stale containers..."

$ProjectName = Split-Path -Leaf (Get-Location)

docker ps -a `
    --filter "label=com.docker.compose.project=$ProjectName" `
    -q | ForEach-Object {
        docker rm -f $_
    }


# ---------------------------------------------------------
# 6. Clear Docker build cache
# ---------------------------------------------------------

Write-Host ""
Write-Host "[5/10] Clearing Docker builder cache..."

docker builder prune -af


# ---------------------------------------------------------
# 7. Pull base images
# ---------------------------------------------------------

Write-Host ""
Write-Host "[6/10] Pulling latest external/base images..."

docker compose -f $ComposeFile pull --ignore-buildable

if ($LASTEXITCODE -ne 0) {
    Write-Host "WARNING: Some images could not be pulled."
    Write-Host "Continuing with locally available images..."
}


# ---------------------------------------------------------
# 8. Build ALL project images with NO CACHE
# ---------------------------------------------------------

Write-Host ""
Write-Host "[7/10] Building all services WITHOUT CACHE..."

docker compose -f $ComposeFile build `
    --no-cache `
    --pull

if ($LASTEXITCODE -ne 0) {
    Write-Host ""
    Write-Host "ERROR: Docker build failed."
    exit 1
}


# ---------------------------------------------------------
# 9. Start complete Docker Compose stack
# ---------------------------------------------------------

Write-Host ""
Write-Host "[8/10] Starting Docker Compose stack..."

docker compose -f $ComposeFile up `
    -d `
    --force-recreate `
    --remove-orphans

if ($LASTEXITCODE -ne 0) {
    Write-Host ""
    Write-Host "ERROR: Docker Compose startup failed."
    exit 1
}


# ---------------------------------------------------------
# 10. Status and logs
# ---------------------------------------------------------

Write-Host ""
Write-Host "[9/10] Waiting for containers..."

Start-Sleep -Seconds 10

docker compose -f $ComposeFile ps


Write-Host ""
Write-Host "[10/10] Checking container logs..."

docker compose -f $ComposeFile logs `
    --tail=100


Write-Host ""
Write-Host "========================================="
Write-Host " REBUILD COMPLETED"
Write-Host "========================================="
Write-Host ""
Write-Host "Useful commands:"
Write-Host ""
Write-Host "Status:"
Write-Host "docker compose -f $ComposeFile ps"
Write-Host ""
Write-Host "All logs:"
Write-Host "docker compose -f $ComposeFile logs -f"
Write-Host ""
Write-Host "Backend logs:"
Write-Host "docker compose -f $ComposeFile logs -f backend"
Write-Host ""
Write-Host "Frontend logs:"
Write-Host "docker compose -f $ComposeFile logs -f frontend"
Write-Host ""