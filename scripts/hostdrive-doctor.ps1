# HostDrive doctor - answers "which helper / job script / Compose stack is the UI
# actually using?" so a hotfix that was extracted but never loaded is obvious.
#
#   powershell -ExecutionPolicy Bypass -File scripts\hostdrive-doctor.ps1
#   powershell -ExecutionPolicy Bypass -File scripts\hostdrive-doctor.ps1 -Fix   # restart stale helper
param(
    [switch]$Fix,
    [int]$Port = $(if ($env:HOST_DRIVE_HELPER_PORT) { [int]$env:HOST_DRIVE_HELPER_PORT } else { 9876 })
)

$ErrorActionPreference = "Continue"
$root = Split-Path -Parent (Split-Path -Parent $MyInvocation.MyCommand.Path)
$rootFull = [System.IO.Path]::GetFullPath($root).TrimEnd('\')
$jobScript = Join-Path $root "scripts\refresh-drive-mounts-job.ps1"
$ensure = Join-Path $root "scripts\ensure-host-drive-helper.ps1"
$problems = @()

function Get-JobVersion([string]$Path) {
    try {
        foreach ($line in @(Get-Content -LiteralPath $Path -TotalCount 40 -ErrorAction Stop)) {
            if (("$line") -match 'AETHERIS_JOB_VERSION:\s*([0-9][0-9A-Za-z.\-]*)') { return $Matches[1] }
        }
        return "legacy (pre-4.6)"
    }
    catch { return "missing" }
}

Write-Host "== This checkout ==" -ForegroundColor Cyan
Write-Host ("  root             : {0}" -f $rootFull)
Write-Host ("  job script       : {0}  (v{1})" -f $jobScript, (Get-JobVersion $jobScript))

Write-Host ""
Write-Host "== Running HostDrive helper (http://127.0.0.1:$Port) ==" -ForegroundColor Cyan
$health = $null
try { $health = Invoke-RestMethod -Uri "http://127.0.0.1:$Port/health" -TimeoutSec 3 } catch { }
if (-not $health) {
    Write-Host "  not reachable" -ForegroundColor Yellow
    $problems += "Helper is not running on port $Port."
}
else {
    $hRoot = [string]$health.root
    Write-Host ("  helper version   : {0}" -f $(if ($health.helper_version) { $health.helper_version } else { "legacy (pre-4.6)" }))
    Write-Host ("  helper pid       : {0}" -f $health.helper_pid)
    Write-Host ("  helper root      : {0}" -f $(if ($hRoot) { $hRoot } else { "(not reported - legacy helper)" }))
    Write-Host ("  job script loaded: {0}  (v{1})" -f $health.job_script, $(if ($health.job_script_version) { $health.job_script_version } else { "?" }))
    if (-not $hRoot) {
        $problems += "Running helper is a pre-4.6 build: it will spawn whatever refresh-drive-mounts-job.ps1 sits in ITS OWN checkout, not this one."
    }
    elseif (-not ([System.IO.Path]::GetFullPath($hRoot).TrimEnd('\')).Equals($rootFull, [StringComparison]::OrdinalIgnoreCase)) {
        $problems += "Running helper belongs to a different checkout: $hRoot (this is $rootFull). Files extracted here are never used by it."
    }
    elseif ([string]$health.job_script_version -ne (Get-JobVersion $jobScript)) {
        $problems += "Helper reports job v$($health.job_script_version) but disk has v$(Get-JobVersion $jobScript)."
    }
}

Write-Host ""
Write-Host "== Compose stacks with an 'api' service ==" -ForegroundColor Cyan
$ids = @()
try { $ids = @(& docker ps --filter "label=com.docker.compose.service=api" --format "{{.ID}}" 2>&1 | ForEach-Object { "$_" } | Where-Object { $_ -match '^[0-9a-f]{6,}$' }) } catch { }
if (-not $ids.Count) { Write-Host "  no running api container found" -ForegroundColor Yellow }
foreach ($id in $ids) {
    try {
        $obj = ((& docker inspect $id 2>&1 | ForEach-Object { "$_" }) -join "`n" | ConvertFrom-Json)[0]
        $l = $obj.Config.Labels
        $work = [string]$l.'com.docker.compose.project.working_dir'
        $proj = [string]$l.'com.docker.compose.project'
        $files = [string]$l.'com.docker.compose.project.config_files'
        $mounts = @($obj.Mounts | Where-Object { $_.Destination -like '/host/*' } | ForEach-Object { "$($_.Destination)<-$($_.Source)" })
        $mine = $work -and ([System.IO.Path]::GetFullPath($work).TrimEnd('\')).Equals($rootFull, [StringComparison]::OrdinalIgnoreCase)
        Write-Host ("  {0,-26} name={1}" -f $proj, $obj.Name.TrimStart('/'))
        Write-Host ("  {0,-26} dir={1} {2}" -f '', $work, $(if ($mine) { "(this checkout)" } else { "(OTHER checkout)" }))
        Write-Host ("  {0,-26} files={1}" -f '', $files)
        Write-Host ("  {0,-26} /host mounts: {1}" -f '', $(if ($mounts.Count) { $mounts -join ', ' } else { 'none' }))
        if (-not $mine) {
            $problems += "Compose project '$proj' was started from $work - if the UI you use is served by it, the hotfix must be applied THERE (or stop that stack)."
        }
    }
    catch { Write-Host "  could not inspect $id" }
}

Write-Host ""
if (-not $problems.Count) {
    Write-Host "OK: helper, job script and Compose stack all belong to $rootFull." -ForegroundColor Green
    exit 0
}
Write-Host "PROBLEMS:" -ForegroundColor Red
foreach ($p in $problems) { Write-Host ("  - {0}" -f $p) -ForegroundColor Red }

if ($Fix) {
    Write-Host ""
    Write-Host "Restarting helper from this checkout..." -ForegroundColor Cyan
    & powershell -NoProfile -ExecutionPolicy Bypass -File $ensure -ForceRestart
    Start-Sleep -Seconds 2
    try {
        $h2 = Invoke-RestMethod -Uri "http://127.0.0.1:$Port/health" -TimeoutSec 3
        Write-Host ("Helper now: root={0} job v{1} pid {2}" -f $h2.root, $h2.job_script_version, $h2.helper_pid) -ForegroundColor Green
    }
    catch { Write-Host "Helper did not come back - see ensure-host-drive-helper.ps1 output above." -ForegroundColor Red }
}
else {
    Write-Host ""
    Write-Host "Run again with -Fix to restart the helper from this checkout." -ForegroundColor Yellow
}
exit 1
