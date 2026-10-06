<#
.SYNOPSIS
  Diagnose Windows/server-side HDD/SSD/USB evidence visibility end-to-end.

.EXAMPLE
  powershell.exe -NoProfile -ExecutionPolicy Bypass -File .\scripts\check-server-evidence-drives.ps1
#>
param(
    [string]$RequiredPath = ""
)

$ErrorActionPreference = "Continue"
$root = Split-Path -Parent (Split-Path -Parent $MyInvocation.MyCommand.Path)

function Write-Section([string]$Title) {
    Write-Host ""
    Write-Host ("=== {0} ===" -f $Title) -ForegroundColor Cyan
}

Write-Section "Windows drive inventory"
$volumes = @()
try {
    $volumes = @(Get-CimInstance Win32_LogicalDisk | Where-Object { $_.DriveType -in @(2,3,4) } | Sort-Object DeviceID)
    foreach ($v in $volumes) {
        $kind = switch ([int]$v.DriveType) { 2 { 'removable' } 3 { 'fixed' } 4 { 'network' } default { 'other' } }
        Write-Host ("{0}  {1,-10}  {2}" -f $v.DeviceID, $kind, $v.VolumeName)
    }
} catch {
    Write-Warning $_.Exception.Message
}

Write-Section "HostDrive helper"
$helper = $null
try {
    $helper = Invoke-RestMethod -Uri 'http://127.0.0.1:9876/drives' -TimeoutSec 8
    Write-Host ("Helper online. Drives: {0}" -f (($helper.drives | ForEach-Object { "$_" }) -join ', ')) -ForegroundColor Green
} catch {
    Write-Warning "HostDrive helper is offline on port 9876."
    Write-Host "Start it with:"
    Write-Host "  powershell.exe -NoProfile -ExecutionPolicy Bypass -File .\scripts\ensure-host-drive-helper.ps1" -ForegroundColor Yellow
}

Write-Section "Forensic API container"
$apiId = ""
try {
    $candidates = @(docker ps --filter 'label=com.docker.compose.service=api' --format '{{.ID}}|{{.Label "com.docker.compose.project"}}|{{.Label "com.docker.compose.project.working_dir"}}')
    foreach ($row in $candidates) {
        $parts = "$row" -split '\|', 3
        if ($parts.Count -lt 2) { continue }
        if ($parts[1] -eq 'aetheris-forensic') { $apiId = $parts[0]; break }
        if (-not $apiId -and $parts.Count -ge 3 -and $parts[2] -like "$root*") { $apiId = $parts[0] }
    }
} catch { }

if (-not $apiId) {
    Write-Warning "No running forensic api container found. Start the forensic stack first."
} else {
    Write-Host "API container: $apiId"
    foreach ($v in $volumes) {
        $letter = ($v.DeviceID -replace ':','').ToLower()
        if (-not $letter) { continue }
        $probe = "/host/$letter"
        $out = docker exec $apiId sh -lc "test -d '$probe' && ls -A '$probe' 2>/dev/null | head -n 1" 2>$null
        if ($LASTEXITCODE -eq 0 -and $out) {
            Write-Host ("{0}: -> {1}  READABLE" -f $letter.ToUpper(), $probe) -ForegroundColor Green
        } else {
            Write-Host ("{0}: -> {1}  NOT MOUNTED/EMPTY" -f $letter.ToUpper(), $probe) -ForegroundColor Yellow
        }
    }
}

if ($RequiredPath) {
    Write-Section "Required evidence path"
    Write-Host $RequiredPath
}

Write-Section "Recommended repair"
Write-Host "1. Ensure helper:"
Write-Host "   powershell.exe -NoProfile -ExecutionPolicy Bypass -File .\scripts\ensure-host-drive-helper.ps1"
Write-Host "2. Refresh newly attached drives:"
Write-Host "   powershell.exe -NoProfile -ExecutionPolicy Bypass -File .\scripts\hostdrive-agent.ps1 -RefreshNow -Once"
if ($RequiredPath) {
    Write-Host "3. Validate exact path:"
    Write-Host ("   powershell.exe -NoProfile -ExecutionPolicy Bypass -File .\scripts\test-dynamic-drive-mounts.ps1 -RequiredPath `"{0}`"" -f $RequiredPath)
}
