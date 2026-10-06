[CmdletBinding()]
param([string]$Root = $PSScriptRoot)

$ErrorActionPreference = 'Stop'

$Root = $Root.Trim()
while ($Root.Length -gt 0 -and ($Root.StartsWith('"') -or $Root.StartsWith("'"))) { $Root = $Root.Substring(1) }
while ($Root.Length -gt 0 -and ($Root.EndsWith('"') -or $Root.EndsWith("'"))) { $Root = $Root.Substring(0, $Root.Length - 1) }
while ($Root.Length -gt 3 -and ($Root.EndsWith('\') -or $Root.EndsWith('/'))) { $Root = $Root.Substring(0, $Root.Length - 1) }
$Root = (Resolve-Path -LiteralPath $Root).Path

$repair = Join-Path $Root 'scripts\Repair-Greenbone-Feed-v1.4.1.ps1'
$cmd = Join-Path $Root 'Repair-Greenbone-Feed.cmd'

Write-Host '=============================================================================='
Write-Host 'Aetheris Greenbone repair install check v1.4.3'
Write-Host '=============================================================================='
Write-Host "Normalized Root=$Root"

foreach ($p in @($repair, $cmd)) {
    if (-not (Test-Path -LiteralPath $p)) { throw "Missing required file: $p" }
    Write-Host "[OK] Exists: $p" -ForegroundColor Green
}

$tokens = $null
$errors = $null
[void][System.Management.Automation.Language.Parser]::ParseFile($repair, [ref]$tokens, [ref]$errors)
if ($errors.Count -gt 0) {
    foreach ($e in $errors) { Write-Host "[FAIL] $($e.Message)" -ForegroundColor Red }
    exit 2
}
Write-Host '[OK] Repair PowerShell script parses successfully.' -ForegroundColor Green

$repairText = Get-Content -LiteralPath $repair -Raw
if ($repairText -match 'function\s+Run-Docker\s*\(\s*\[string\[\]\]\$Args') {
    throw 'Old broken Run-Docker $Args parameter is still present.'
}
if ($repairText -match 'function\s+Compose\s*\(\s*\[string\[\]\]\$Args') {
    throw 'Old broken Compose $Args parameter is still present.'
}
if ($repairText -notmatch 'function\s+Run-Docker\s*\(\s*\[string\[\]\]\$ArgumentList') {
    throw 'v1.4.3 Run-Docker ArgumentList fix is missing.'
}
if ($repairText -notmatch 'function\s+Compose\s*\(\s*\[string\[\]\]\$ComposeArguments') {
    throw 'v1.4.3 ComposeArguments fix is missing.'
}
if ($repairText -notmatch "config', '--services") {
    throw 'v1.4.3 Docker Compose preflight is missing.'
}
Write-Host '[OK] Docker argument forwarding fix is installed.' -ForegroundColor Green

$cmdText = Get-Content -LiteralPath $cmd -Raw
if ($cmdText -notmatch 'for %%I in \("%ROOT%\."\) do set "ROOT=%%~fI"') {
    throw 'CMD trailing-slash normalization is missing.'
}
Write-Host '[OK] CMD path normalization is installed.' -ForegroundColor Green
Write-Host '[OK] Installation check passed.' -ForegroundColor Green
exit 0
