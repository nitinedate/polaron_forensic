# Polaron V39 one-click Windows HostDrive restart.
# Replaces any already-running pre-V39 auto-remount watcher with the
# detection-only watcher used by the Server drives browser.
param([switch]$SkipAgentInstall)

$ErrorActionPreference = "Stop"
$root = Split-Path -Parent (Split-Path -Parent $MyInvocation.MyCommand.Path)
$ensure = Join-Path $root "scripts\ensure-host-drive-helper.ps1"
$install = Join-Path $root "scripts\install-hostdrive-agent.ps1"

if (-not $SkipAgentInstall) {
    Write-Host "Installing/restarting V39 HostDrive agent (detection only)..." -ForegroundColor Cyan
    & powershell.exe -NoProfile -ExecutionPolicy Bypass -File $install
    if ($LASTEXITCODE -ne 0) { throw "install-hostdrive-agent.ps1 failed (exit $LASTEXITCODE)" }
}

Write-Host "Restarting V39 HostDrive helper..." -ForegroundColor Cyan
& powershell.exe -NoProfile -ExecutionPolicy Bypass -File $ensure -ForceRestart
if ($LASTEXITCODE -ne 0) { throw "ensure-host-drive-helper.ps1 failed (exit $LASTEXITCODE)" }

$health = Invoke-RestMethod -Uri "http://127.0.0.1:9876/health" -TimeoutSec 5
if (-not $health.ok) { throw "HostDrive helper did not become healthy." }
$drives = Invoke-RestMethod -Uri "http://127.0.0.1:9876/drives" -TimeoutSec 10
Write-Host ("HostDrive helper v{0} online. Server drives: {1}" -f $health.helper_version, (@($drives.drives) -join ', ')) -ForegroundColor Green
Write-Host "No Docker remount was performed. Select the exact evidence folder in the UI to mount it only when needed." -ForegroundColor Green
