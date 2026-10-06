[CmdletBinding()]
param([string]$Root = $PSScriptRoot)

$ErrorActionPreference = 'Stop'

$Root = $Root.Trim()
while ($Root.Length -gt 0 -and ($Root.StartsWith('"') -or $Root.StartsWith("'"))) { $Root = $Root.Substring(1) }
while ($Root.Length -gt 0 -and ($Root.EndsWith('"') -or $Root.EndsWith("'"))) { $Root = $Root.Substring(0, $Root.Length - 1) }
while ($Root.Length -gt 3 -and ($Root.EndsWith('\\') -or $Root.EndsWith('/'))) { $Root = $Root.Substring(0, $Root.Length - 1) }
$Root = (Resolve-Path -LiteralPath $Root).Path

$repair = Join-Path $Root 'scripts\Repair-Greenbone-Feed-v1.4.1.ps1'
$cmd = Join-Path $Root 'Repair-Greenbone-Feed.cmd'

Write-Host '=============================================================================='
Write-Host 'Aetheris Greenbone repair install check v1.4.2'
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

$cmdText = Get-Content -LiteralPath $cmd -Raw
if ($cmdText -notmatch 'for %%I in \("%ROOT%\."\) do set "ROOT=%%~fI"') {
    throw 'Repair-Greenbone-Feed.cmd does not contain the v1.4.2 trailing-slash normalization.'
}
Write-Host '[OK] CMD wrapper strips the trailing backslash before passing -Root.' -ForegroundColor Green
Write-Host '[OK] Installation check passed.' -ForegroundColor Green
exit 0
