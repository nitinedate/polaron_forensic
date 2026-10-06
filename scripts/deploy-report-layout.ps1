<#
.SYNOPSIS
  Deploy Report Generator Agent layout fixes (white letterhead, packed pages,
  no Evidence Details, body above page number) without tearing down volumes.

.DESCRIPTION
  Rebuilds the gateway UI and recreates forensic api + worker-report so Python
  and preview layout changes are live.

  Never runs `docker compose down -v`.
  Recreates api/worker-report WITHOUT docker-compose.drives.forensic.yml so a
  missing host G: volume cannot leave containers in Created/not-running.

.EXAMPLE
  powershell -NoProfile -ExecutionPolicy Bypass -File .\scripts\deploy-report-layout.ps1

.EXAMPLE
  .\Deploy-Report-Layout.cmd
#>
param(
    [switch]$SkipGateway,
    [switch]$SkipApi,
    [switch]$SkipLetterhead,
    [switch]$NoBuild
)

$ErrorActionPreference = "Stop"
$root = Split-Path -Parent (Split-Path -Parent $MyInvocation.MyCommand.Path)
Set-Location $root

function Write-Step([string]$Message) {
    Write-Host ""
    Write-Host "==> $Message" -ForegroundColor Cyan
}

function Get-Docker {
    $docker = Get-Command docker -ErrorAction SilentlyContinue
    if (-not $docker) {
        $dockerExe = "C:\Program Files\Docker\Docker\resources\bin\docker.exe"
        if (Test-Path $dockerExe) { return $dockerExe }
        throw "docker.exe not found. Start Docker Desktop and retry."
    }
    return $docker.Source
}

function Invoke-Docker {
    param([Parameter(Mandatory = $true)][string[]]$Arguments, [string]$FailureMessage)
    & $script:Docker @Arguments
    if ($LASTEXITCODE -ne 0) {
        throw ($FailureMessage + " (exit $LASTEXITCODE)")
    }
}

function Wait-Healthy {
    param(
        [string]$Container,
        [int]$TimeoutSec = 120
    )
    $deadline = (Get-Date).AddSeconds($TimeoutSec)
    while ((Get-Date) -lt $deadline) {
        $status = (& $script:Docker inspect --format "{{.State.Status}}" $Container 2>$null)
        $health = (& $script:Docker inspect --format "{{if .State.Health}}{{.State.Health.Status}}{{else}}none{{end}}" $Container 2>$null)
        if ($status -eq "running" -and ($health -eq "healthy" -or $health -eq "none")) {
            return $true
        }
        Start-Sleep -Seconds 2
    }
    return $false
}

$script:Docker = Get-Docker
Write-Host "Aetheris report-layout deploy"
Write-Host "Root: $root"
Write-Host "Docker: $script:Docker"
Write-Host "Safety: never uses docker compose down -v"

# --- 1) White letterhead PNGs (header/footer paper fill) --------------------
if (-not $SkipLetterhead) {
    Write-Step "Flatten letterhead header/footer onto white paper"
    $headerSrc = Join-Path $root "backend\app\static\report\letterhead-header.png"
    $footerSrc = Join-Path $root "backend\app\static\report\letterhead-footer.png"
    $publicReport = Join-Path $root "frontend\public\report"
    if (-not (Test-Path $publicReport)) {
        New-Item -ItemType Directory -Force -Path $publicReport | Out-Null
    }

    $apiName = "aetheris-forensic-api-1"
    $apiRunning = (& $script:Docker ps --filter "name=$apiName" --format "{{.Names}}" 2>$null)
    if ($apiRunning -match $apiName) {
        Invoke-Docker -Arguments @(
            "exec", $apiName, "python", "-c",
            "from app.services.report_letterhead import rewrite_white_letterhead_assets; print([str(p) for p in rewrite_white_letterhead_assets()])"
        ) -FailureMessage "Letterhead flatten failed inside $apiName"
    }
    else {
        Write-Host "API container not running yet; skipping in-container flatten (will use on-disk PNGs)."
    }

    if ((Test-Path $headerSrc) -and (Test-Path $footerSrc)) {
        Copy-Item $headerSrc (Join-Path $publicReport "letterhead-header.png") -Force
        Copy-Item $footerSrc (Join-Path $publicReport "letterhead-footer.png") -Force
        Write-Host "Copied white letterhead assets into frontend\public\report"
    }
    else {
        Write-Warning "Letterhead PNGs missing under backend\app\static\report — gateway will keep previous assets."
    }
}

# --- 2) Gateway (preview CSS + pagination + hide Evidence Details) ----------
if (-not $SkipGateway) {
    Write-Step "Rebuild and restart aetheris-gateway"
    $gwArgs = @(
        "compose",
        "--project-directory", $root,
        "--project-name", "aetheris-gateway",
        "-f", "services/gateway/docker-compose.yml",
        "up", "-d"
    )
    if (-not $NoBuild) { $gwArgs += "--build" }
    Invoke-Docker -Arguments $gwArgs -FailureMessage "Gateway deploy failed"
    if (-not (Wait-Healthy -Container "aetheris-gateway-gateway-1" -TimeoutSec 90)) {
        Write-Warning "Gateway container may still be starting. Check: docker ps --filter name=aetheris-gateway"
    }
    else {
        Write-Host "Gateway is up (http://localhost:3000)"
    }
}

# --- 3) Forensic API + report worker (no drives overlay) --------------------
if (-not $SkipApi) {
    Write-Step "Recreate forensic api + worker-report (no G: drives overlay)"
    # Intentionally omit docker-compose.drives.forensic.yml — missing hostdrive_g_*
    # volumes leave api/worker-report in Created and block report generation.
    $apiArgs = @(
        "compose",
        "--project-directory", $root,
        "--project-name", "aetheris-forensic",
        "-f", "services/forensic/docker-compose.yml",
        "up", "-d",
        "--no-deps",
        "--force-recreate"
    )
    if (-not $NoBuild) { $apiArgs += "--build" }
    $apiArgs += @("api", "worker-report")
    Invoke-Docker -Arguments $apiArgs -FailureMessage "Forensic api/worker-report recreate failed"

    if (-not (Wait-Healthy -Container "aetheris-forensic-api-1" -TimeoutSec 180)) {
        throw "aetheris-forensic-api-1 did not become healthy. Check: docker logs aetheris-forensic-api-1 --tail 80"
    }
    Write-Host "API healthy."

    $wr = (& $script:Docker ps --filter "name=aetheris-forensic-worker-report-1" --format "{{.Status}}" 2>$null)
    if (-not $wr) {
        throw "aetheris-forensic-worker-report-1 is not running."
    }
    Write-Host "worker-report: $wr"

    # Re-run letterhead flatten now that API is definitely up with latest code.
    if (-not $SkipLetterhead) {
        Write-Step "Re-apply white letterhead on live API mount"
        try {
            Invoke-Docker -Arguments @(
                "exec", "aetheris-forensic-api-1", "python", "-c",
                "from app.services.report_letterhead import rewrite_white_letterhead_assets; print([str(p) for p in rewrite_white_letterhead_assets()])"
            ) -FailureMessage "Post-recreate letterhead flatten failed"
            $publicReport = Join-Path $root "frontend\public\report"
            Copy-Item (Join-Path $root "backend\app\static\report\letterhead-header.png") (Join-Path $publicReport "letterhead-header.png") -Force
            Copy-Item (Join-Path $root "backend\app\static\report\letterhead-footer.png") (Join-Path $publicReport "letterhead-footer.png") -Force
        }
        catch {
            Write-Warning $_.Exception.Message
        }
    }
}

# --- 4) Smoke checks --------------------------------------------------------
Write-Step "Smoke checks"
& $script:Docker ps --filter "name=aetheris-gateway-gateway-1" --filter "name=aetheris-forensic-api-1" --filter "name=aetheris-forensic-worker-report-1" --format "table {{.Names}}\t{{.Status}}"
try {
    $health = Invoke-RestMethod "http://127.0.0.1:8080/health" -TimeoutSec 5
    Write-Host "API /health: OK"
}
catch {
    Write-Warning "API /health not reachable yet on :8080 — confirm port publish if needed."
}

Write-Host ""
Write-Host "Deploy complete." -ForegroundColor Green
Write-Host "Next: open the report editor, hard-refresh (Ctrl+F5), then click Recreate report."
Write-Host "Expected: no Evidence Details page; body stays above Page N; letterhead paper is white."
