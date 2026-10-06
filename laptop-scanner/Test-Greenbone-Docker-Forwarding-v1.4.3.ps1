[CmdletBinding()]
param([string]$Root = $PSScriptRoot)

$ErrorActionPreference = 'Stop'

function Invoke-Docker([string[]]$ArgumentList) {
    $old = $ErrorActionPreference
    try {
        $ErrorActionPreference = 'Continue'
        $output = & docker.exe @ArgumentList 2>&1
        $exitCode = $LASTEXITCODE
    }
    finally {
        $ErrorActionPreference = $old
    }
    $text = (@($output | ForEach-Object { $_.ToString() }) -join [Environment]::NewLine)
    return [pscustomobject]@{ ExitCode = $exitCode; Text = $text }
}

$Root = $Root.Trim().Trim('"').Trim("'")
while ($Root.Length -gt 3 -and ($Root.EndsWith('\') -or $Root.EndsWith('/'))) { $Root = $Root.Substring(0, $Root.Length - 1) }
$Root = (Resolve-Path -LiteralPath $Root).Path
$compose = Join-Path $Root 'docker-compose.yml'
if (-not (Test-Path -LiteralPath $compose)) { throw "Missing compose file: $compose" }

Write-Host '=============================================================================='
Write-Host 'Aetheris Docker command forwarding check v1.4.3'
Write-Host '=============================================================================='
Write-Host "Root=$Root"
Write-Host "Compose=$compose"

$r = Invoke-Docker -ArgumentList @('info', '--format', '{{.ServerVersion}}')
if ($r.ExitCode -ne 0) { throw "docker info failed:`n$($r.Text)" }
Write-Host "[OK] Docker engine: $($r.Text.Trim())" -ForegroundColor Green

$r = Invoke-Docker -ArgumentList @('compose', 'version', '--short')
if ($r.ExitCode -ne 0) { throw "docker compose version failed:`n$($r.Text)" }
Write-Host "[OK] Docker Compose: $($r.Text.Trim())" -ForegroundColor Green

$r = Invoke-Docker -ArgumentList @('compose', '--project-directory', $Root, '-f', $compose, 'config', '--services')
if ($r.ExitCode -ne 0) { throw "docker compose config --services failed:`n$($r.Text)" }
$services = @(($r.Text -split '\r?\n') | ForEach-Object { $_.Trim() } | Where-Object { $_ })
foreach ($required in @('gvmd','ospd-openvas','scanner-agent','vulnerability-tests','data-objects')) {
    if ($services -notcontains $required) { throw "Required service missing from Compose config: $required" }
}
Write-Host "[OK] Compose argument forwarding works; $($services.Count) services detected." -ForegroundColor Green
Write-Host ('[OK] Required Greenbone services: {0}' -f ((@('gvmd','ospd-openvas','scanner-agent','vulnerability-tests','data-objects')) -join ', ')) -ForegroundColor Green
exit 0
