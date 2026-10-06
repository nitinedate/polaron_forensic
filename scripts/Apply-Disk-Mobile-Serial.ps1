[CmdletBinding()]
param(
    [ValidateSet("forensic", "mobile-android", "mobile-ios", "mobile-extract")]
    [string[]]$Products = @(),
    [string]$ForensicProjectName = "aetheris-forensic",
    [hashtable]$ComposeOverrides = @{},
    [switch]$SkipGateway,
    [switch]$PrepareVisionModel,
    [switch]$ReprocessReady,
    [switch]$DryRun
)

$ErrorActionPreference = "Stop"
$Root = Split-Path -Parent (Split-Path -Parent $MyInvocation.MyCommand.Path)
$Docker = (Get-Command docker -ErrorAction Stop).Source

function Invoke-Docker([string[]]$Arguments) {
    Write-Host ("docker " + ($Arguments -join " "))
    if (-not $DryRun) {
        & $Docker @Arguments
        if ($LASTEXITCODE -ne 0) { throw "Docker failed with exit $LASTEXITCODE" }
    }
}

function Get-Project([string]$Product) {
    if ($Product -eq "forensic") { return $ForensicProjectName }
    return "aetheris-$Product"
}

function Get-Compose([string]$Product) {
    $result = @("compose", "--project-directory", $Root, "--project-name", (Get-Project $Product),
        "-f", (Join-Path $Root "services\$Product\docker-compose.yml"))
    $drive = switch ($Product) {
        "forensic" { "docker-compose.drives.forensic.yml" }
        "mobile-android" { "docker-compose.drives.mobile-android.yml" }
        "mobile-ios" { "docker-compose.drives.mobile-ios.yml" }
        "mobile-extract" { "docker-compose.drives.mobile.yml" }
    }
    $drivePath = Join-Path $Root $drive
    if (Test-Path $drivePath) { $result += @("-f", $drivePath) }
    if ($ComposeOverrides.ContainsKey($Product)) {
        foreach ($path in @($ComposeOverrides[$Product])) { $result += @("-f", $path) }
    }
    return $result
}

$Candidates = @("forensic", "mobile-android", "mobile-ios", "mobile-extract")
if ($Products.Count -eq 0) {
    foreach ($product in $Candidates) {
        $project = Get-Project $product
        $running = @(& $Docker ps --filter "label=com.docker.compose.project=$project" --format "{{.ID}}")
        if ($LASTEXITCODE -ne 0) { throw "Cannot inspect Docker containers" }
        if ($running.Count -gt 0) { $Products += $product }
    }
}
if ($Products.Count -eq 0) { throw "No running Disk/Mobile product found. Supply -Products and the existing project name if needed." }

# Archive overlays do not delete files that belonged to older releases. These
# three retired outside-process agents are not imported by the current tasks.
# Shared thermal/performance helpers and recovery audit storage remain required.
foreach ($retired in @("observe_agent.py", "performance_agent.py", "repair_agent.py")) {
    $retiredPath = Join-Path $Root ("backend\app\services\" + $retired)
    if (Test-Path -LiteralPath $retiredPath) {
        Write-Host ("Removing retired agent source: " + $retired)
        if (-not $DryRun) { Remove-Item -LiteralPath $retiredPath -Force }
    }
}

$Targets = @{}
foreach ($product in $Products) {
    $project = Get-Project $product
    $ui = @(& $Docker ps --filter "label=com.docker.compose.project=$project" --filter "label=com.docker.compose.service=frontend" --format "{{.ID}}")
    if ($LASTEXITCODE -ne 0) { throw "Cannot inspect the frontend" }
    $services = switch ($product) {
        "forensic" { @("api", "worker-disk", "worker-parse", "worker-rag-gpu", "worker-ocr-gpu", "worker-report", "worker-agent", "worker-beat") }
        "mobile-android" { @("api", "worker-build", "worker-parse", "worker-rag", "worker-ocr", "worker-report", "worker-beat") }
        "mobile-ios" { @("api", "worker-build", "worker-parse", "worker-rag", "worker-ocr", "worker-report", "worker-beat") }
        "mobile-extract" { @("api", "worker-mobile", "worker-beat", "worker-ocr-gpu", "worker-rag-gpu") }
    }
    if ($ui.Count -gt 0) { $services += "frontend" }
    $services += "worker-progress"
    $Targets[$product] = $services
    $build = @("api")
    if ($ui.Count -gt 0) { $build += "frontend" }
    Invoke-Docker ((Get-Compose $product) + @("build", "--no-cache") + $build)
}

# Finish builds before stopping the existing application workers.
foreach ($product in $Products) {
    $compose = Get-Compose $product
    Invoke-Docker ($compose + @("stop", "-t", "120") + $Targets[$product])
    # Clean up obsolete monitoring containers left outside the current Compose
    # services. Limit removal to this exact product project and named agents;
    # never remove processing workers, queues, evidence or Docker volumes.
    foreach ($retiredService in @("worker-observe", "worker-performance", "worker-repair",
        "observe-agent", "performance-agent", "repair-agent")) {
        $retiredIds = @(& $Docker ps -a --filter ("label=com.docker.compose.project=" + (Get-Project $product)) `
            --filter ("label=com.docker.compose.service=" + $retiredService) --format "{{.ID}}")
        if ($LASTEXITCODE -ne 0) { throw "Cannot inspect retired agent containers" }
        if ($retiredIds.Count -gt 0) { Invoke-Docker (@("rm", "-f") + $retiredIds) }
    }
}
foreach ($product in $Products) {
    $compose = Get-Compose $product
    Invoke-Docker ($compose + @("up", "-d", "--no-deps", "--force-recreate", "--wait", "--wait-timeout", "300", "api"))
    Invoke-Docker ($compose + @("exec", "-T", "api", "python", "/scripts/migrate-forensic-serial.py"))
    if ($PrepareVisionModel) {
        Invoke-Docker ($compose + @("exec", "-T", "api", "python", "/scripts/migrate-forensic-serial.py", "--prepare-vision-model"))
    }
    $workers = @($Targets[$product] | Where-Object { $_ -ne "api" })
    Invoke-Docker ($compose + @("up", "-d", "--no-deps", "--force-recreate") + $workers)
    $adopt = @("exec", "-T", "api", "python", "/scripts/migrate-forensic-serial.py", "--adopt-active")
    if ($ReprocessReady) { $adopt += "--reprocess-ready" }
    Invoke-Docker ($compose + $adopt)
    Invoke-Docker ($compose + @("ps"))
}

if (-not $SkipGateway) {
    $gateway = @(& $Docker ps --filter "label=com.docker.compose.project=aetheris-gateway" --filter "label=com.docker.compose.service=gateway" --format "{{.ID}}")
    if ($LASTEXITCODE -ne 0) { throw "Cannot inspect the gateway" }
    if ($gateway.Count -gt 0) {
        $compose = @("compose", "--project-directory", $Root, "--project-name", "aetheris-gateway",
            "-f", (Join-Path $Root "services\gateway\docker-compose.yml"))
        Invoke-Docker ($compose + @("build", "--no-cache", "gateway"))
        Invoke-Docker ($compose + @("up", "-d", "--no-deps", "--force-recreate", "gateway"))
    }
}
Write-Host "Disk/Mobile serial update finished. See DISK-MOBILE-SERIAL-RELEASE.md for verification and recovery."
