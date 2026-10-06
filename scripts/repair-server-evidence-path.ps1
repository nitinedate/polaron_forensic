<#
.SYNOPSIS
  Repair and verify one server-accessible evidence path without copying evidence.

.EXAMPLE
  powershell.exe -NoProfile -ExecutionPolicy Bypass -File .\scripts\repair-server-evidence-path.ps1 -RequiredPath "G:\Cases\Disk01.E01"
#>
param(
    [Parameter(Mandatory = $true)][string]$RequiredPath
)

$ErrorActionPreference = 'Stop'
$root = Split-Path -Parent (Split-Path -Parent $MyInvocation.MyCommand.Path)
$refresh = Join-Path $root 'scripts\refresh-drive-mounts-job.ps1'
$statusDir = Join-Path $root '.runtime\hostdrive'
$status = Join-Path $statusDir 'manual-repair.json'

if (-not (Test-Path -LiteralPath $RequiredPath)) {
    throw "Windows cannot see the selected evidence path: $RequiredPath"
}
if (-not (Test-Path -LiteralPath $refresh)) {
    throw "Missing refresh script: $refresh"
}
New-Item -ItemType Directory -Force -Path $statusDir | Out-Null
Remove-Item -LiteralPath $status -Force -ErrorAction SilentlyContinue

Write-Host "[1/2] Repairing Docker read-only access to: $RequiredPath" -ForegroundColor Cyan
& $refresh -Root $root -StatusFile $status -RequiredPath $RequiredPath
$rc = $LASTEXITCODE

Write-Host "[2/2] Result" -ForegroundColor Cyan
if (Test-Path -LiteralPath $status) {
    $raw = Get-Content -LiteralPath $status -Raw
    Write-Host $raw
    try {
        $result = $raw | ConvertFrom-Json
        if (-not $result.ok) {
            throw $(if ($result.error) { [string]$result.error } elseif ($result.message) { [string]$result.message } else { 'Server evidence mount repair failed' })
        }
        Write-Host ("[OK] mode={0} source={1}" -f $result.mount_mode, $result.mount_source) -ForegroundColor Green
    }
    catch {
        if ($rc -ne 0) { throw }
    }
}
elseif ($rc -ne 0) {
    throw "Drive refresh failed with exit code $rc and produced no status file."
}

if ($rc -ne 0) { exit $rc }
