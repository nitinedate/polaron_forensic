<#
Build/recreate the single Enterprise Console gateway only.
This intentionally does NOT start Redis/Postgres/MinIO or the legacy root frontend.
#>
[CmdletBinding()]
param(
    [switch]$NoCache,
    [switch]$Pull
)

$ErrorActionPreference = 'Stop'
$root = Split-Path -Parent (Split-Path -Parent $MyInvocation.MyCommand.Path)
$docker = Get-Command docker -ErrorAction SilentlyContinue
if (-not $docker) { throw 'docker.exe was not found in PATH.' }

$common = @(
    'compose', '--project-directory', $root,
    '--project-name', 'aetheris-gateway',
    '-f', (Join-Path $root 'services\gateway\docker-compose.yml')
)

$build = @('build')
if ($NoCache) { $build += '--no-cache' }
if ($Pull) { $build += '--pull' }
$build += 'gateway'

Write-Host 'Building Enterprise Console gateway...' -ForegroundColor Cyan
& $docker.Source @common @build
if ($LASTEXITCODE -ne 0) { throw "Gateway build failed (exit $LASTEXITCODE)." }

Write-Host 'Recreating Enterprise Console gateway...' -ForegroundColor Cyan
& $docker.Source @common up -d --no-deps gateway
if ($LASTEXITCODE -ne 0) { throw "Gateway startup failed (exit $LASTEXITCODE)." }

Write-Host ''
Write-Host 'Enterprise Console updated:' -ForegroundColor Green
Write-Host '  http://localhost:3000'
Write-Host '  http://localhost:3001'
Write-Host 'No Redis/Postgres/MinIO containers were started by this command.' -ForegroundColor DarkGray
