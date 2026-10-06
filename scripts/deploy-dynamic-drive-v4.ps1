<#
.SYNOPSIS
  Deploy the Aetheris dynamic removable-drive v4 fix without touching data volumes.

.EXAMPLE
  powershell -NoProfile -ExecutionPolicy Bypass -File .\scripts\deploy-dynamic-drive-v4.ps1 `
    -RequiredPath "G:\Ex.1 Darshan SSD 256"

This script never tears down the stack or removes Docker data volumes.
#>
param(
    [string]$RequiredPath = ""
)

$ErrorActionPreference = "Stop"
$root = Split-Path -Parent (Split-Path -Parent $MyInvocation.MyCommand.Path)
Set-Location $root

function Get-ActiveComposeContext {
    $files = @()
    $project = ""
    $selected = $null
    $rootFull = [System.IO.Path]::GetFullPath($root).TrimEnd('\')
    $ids = @(& docker ps --filter "label=com.docker.compose.service=api" --format "{{.ID}}" 2>$null)
    foreach ($candidate in $ids) {
        $id = ("$candidate").Trim()
        if (-not $id) { continue }
        try {
            $obj = (& docker inspect $id 2>$null | ConvertFrom-Json)[0]
            $working = [string]$obj.Config.Labels.'com.docker.compose.project.working_dir'
            if ($working) {
                try { $working = [System.IO.Path]::GetFullPath($working).TrimEnd('\') } catch { }
            }
            if (-not $selected) { $selected = $obj }
            if ($working -and $working.Equals($rootFull, [StringComparison]::OrdinalIgnoreCase)) {
                $selected = $obj
                break
            }
        }
        catch { }
    }
    if ($selected) {
        $project = [string]$selected.Config.Labels.'com.docker.compose.project'
        $cfg = [string]$selected.Config.Labels.'com.docker.compose.project.config_files'
        foreach ($part in @($cfg -split ',')) {
            $f = ("$part").Trim().Trim('"')
            if (-not $f) { continue }
            if (-not [System.IO.Path]::IsPathRooted($f)) { $f = Join-Path $root $f }
            if ((Split-Path -Leaf $f) -eq 'docker-compose.drives.generated.yml') { continue }
            if (Test-Path -LiteralPath $f) { $files += [System.IO.Path]::GetFullPath($f) }
        }
    }
    if (-not $files.Count) {
        $files = @(Join-Path $root 'docker-compose.yml')
    }
    return @{ files = @($files | Select-Object -Unique); project = $project }
}

function Get-ComposeArgs([hashtable]$Context, [switch]$WithDrives) {
    $a = @('compose')
    if ($Context.project) { $a += @('-p', [string]$Context.project) }
    foreach ($f in @($Context.files)) { $a += @('-f', [string]$f) }
    if ($WithDrives) { $a += @('-f', (Join-Path $root 'docker-compose.drives.generated.yml')) }
    return $a
}

function Wait-Helper {
    for ($i=0; $i -lt 30; $i++) {
        try {
            $h = Invoke-RestMethod 'http://127.0.0.1:9876/health' -TimeoutSec 2
            if ($h.ok) { return $true }
        }
        catch { }
        Start-Sleep -Seconds 1
    }
    return $false
}

function Wait-RefreshIdle {
    param([int]$TimeoutSec = 600)
    $deadline = (Get-Date).AddSeconds($TimeoutSec)
    while ((Get-Date) -lt $deadline) {
        try {
            $s = Invoke-RestMethod 'http://127.0.0.1:9876/refresh-drive-mounts' -TimeoutSec 5
            if ($s.status -ne 'running') { return $s }
        }
        catch { }
        Start-Sleep -Seconds 2
    }
    throw 'Timed out waiting for the current drive refresh to finish.'
}

function Invoke-ExactRefresh {
    param([string]$Path)
    $normalized = $Path.Trim() -replace '/', '\'
    if ($normalized -notmatch '^[A-Za-z]:[\\/]') {
        throw "RequiredPath must be an absolute Windows drive path, for example G:\Evidence\Case01"
    }
    if (-not (Test-Path -LiteralPath $normalized)) {
        throw "Windows cannot see the selected path: $normalized"
    }

    # Join/finish any automatic drive-change refresh first, then submit the exact
    # path so the same route used by React performs content verification.
    Wait-RefreshIdle | Out-Null
    $body = @{ required_path = $normalized } | ConvertTo-Json -Compress
    $started = $false
    for ($attempt=0; $attempt -lt 3 -and -not $started; $attempt++) {
        try {
            $r = Invoke-RestMethod 'http://127.0.0.1:9876/refresh-drive-mounts' -Method POST `
                -ContentType 'application/json' -Body $body -TimeoutSec 30
            $started = $true
        }
        catch {
            if ($_.Exception.Response -and [int]$_.Exception.Response.StatusCode -eq 409) {
                Wait-RefreshIdle | Out-Null
                continue
            }
            throw
        }
    }
    if (-not $started) { throw 'Could not start exact drive refresh after waiting for the background agent.' }

    $deadline = (Get-Date).AddMinutes(10)
    while ((Get-Date) -lt $deadline) {
        Start-Sleep -Seconds 2
        $s = Invoke-RestMethod 'http://127.0.0.1:9876/refresh-drive-mounts' -TimeoutSec 5
        if ($s.status -eq 'done') {
            if (-not $s.ok) { $msg = if ($s.error) { [string]$s.error } else { [string]$s.message }; throw $msg }
            return $s
        }
        if ($s.status -eq 'error') {
            $msg = if ($s.error) { [string]$s.error } else { [string]$s.message }
            throw $msg
        }
    }
    throw 'Exact drive refresh timed out after 10 minutes.'
}

Write-Host "`n=== Aetheris Dynamic Drive v4 ===" -ForegroundColor Cyan
Write-Host "Project: $root"

# PowerShell 5.1 is the target; verify required files before touching services.
foreach ($required in @(
    'scripts\resolve-docker-drive-source.ps1',
    'scripts\generate-drive-mounts.ps1',
    'scripts\refresh-drive-mounts-job.ps1',
    'scripts\host-drive-helper.ps1',
    'scripts\hostdrive-agent.ps1',
    'scripts\install-hostdrive-agent.ps1'
)) {
    if (-not (Test-Path -LiteralPath (Join-Path $root $required))) {
        throw "Patch is incomplete; missing $required"
    }
}

$ctx = Get-ActiveComposeContext
Write-Host "Active Compose files:" -ForegroundColor Cyan
$ctx.files | ForEach-Object { Write-Host "  $_" }
if ($ctx.project) { Write-Host "Compose project: $($ctx.project)" }

Write-Host "`n=== Reinstalling single HostDrive watcher ===" -ForegroundColor Cyan
& powershell.exe -NoProfile -ExecutionPolicy Bypass -File (Join-Path $root 'scripts\install-hostdrive-agent.ps1')
$installerExit = $LASTEXITCODE
if ($installerExit -ne 0) {
    Write-Warning "HostDrive watcher installer returned exit code $installerExit. Continuing with direct helper recovery; watcher installation is not allowed to block the drive fix."
}
if (-not (Wait-Helper)) {
    Write-Host "HostDrive helper is not healthy yet; starting it directly..." -ForegroundColor Yellow
    & powershell.exe -NoProfile -ExecutionPolicy Bypass -File (Join-Path $root 'scripts\ensure-host-drive-helper.ps1') -ForceRestart
    $helperExit = $LASTEXITCODE
    if ($helperExit -ne 0 -or -not (Wait-Helper)) {
        throw 'HostDrive helper did not become healthy on 127.0.0.1:9876. Run scripts\ensure-host-drive-helper.ps1 -ForceRestart to inspect the helper startup error.'
    }
}
Write-Host "HostDrive helper is healthy on http://127.0.0.1:9876/health" -ForegroundColor Green

Write-Host "`n=== Rebuilding only the React frontend ===" -ForegroundColor Cyan
$cargs = @(Get-ComposeArgs -Context $ctx)
& docker @cargs build frontend
if ($LASTEXITCODE -ne 0) { throw 'Frontend build failed.' }
& docker @cargs up -d --no-deps --force-recreate frontend
if ($LASTEXITCODE -ne 0) { throw 'Frontend restart failed.' }

if ($RequiredPath) {
    Write-Host "`n=== Verifying exact selected evidence path ===" -ForegroundColor Cyan
    $state = Invoke-ExactRefresh -Path $RequiredPath
    Write-Host "PASS: $RequiredPath" -ForegroundColor Green
    Write-Host "Mount mode: $($state.mount_mode)"
    Write-Host "Mount source: $($state.mount_source)"
    if ($state.wsl_distro) { Write-Host "WSL distro: $($state.wsl_distro)" }
}

Write-Host "`n=== Agent status ===" -ForegroundColor Cyan
Get-ScheduledTask -TaskName 'AetherisHostDriveAgent' -ErrorAction SilentlyContinue |
    Select-Object TaskName,State | Format-Table -AutoSize

Write-Host "`nDynamic drive v4 deployment complete. No Docker data volumes were removed." -ForegroundColor Green
