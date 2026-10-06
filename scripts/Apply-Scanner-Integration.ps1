param(
    [string]$ProjectName = 'aetheris-vuln',
    [string[]]$ComposeOverrides = @(),
    [switch]$IncludeGateway,
    [switch]$ValidateOnly
)
$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest
$repo = Split-Path -Parent $PSScriptRoot
Set-Location -LiteralPath $repo
$composeArgs = @('compose', '--project-directory', $repo, '--project-name', $ProjectName, '-f', 'services/vuln/docker-compose.yml')
foreach ($overlay in $ComposeOverrides) { $composeArgs += @('-f', $overlay) }
function Invoke-VulnCompose([string[]]$Arguments) {
    & docker @composeArgs @Arguments
    if ($LASTEXITCODE -ne 0) { throw "Vulnerability deployment command failed: $($Arguments -join ' ')" }
}
Invoke-VulnCompose -Arguments @('config', '--quiet')
if (-not $ValidateOnly) {
    Invoke-VulnCompose -Arguments @('build', '--no-cache', 'api', 'worker-nessus', 'frontend')
    Invoke-VulnCompose -Arguments @('up', '-d', '--no-deps', '--force-recreate', 'api', 'worker-nessus', 'frontend')
    if ($IncludeGateway) {
        & docker compose --project-directory $repo --project-name aetheris-gateway -f services/gateway/docker-compose.yml build --no-cache gateway
        if ($LASTEXITCODE -ne 0) { throw 'Gateway build failed' }
        & docker compose --project-directory $repo --project-name aetheris-gateway -f services/gateway/docker-compose.yml up -d --no-deps --force-recreate gateway
        if ($LASTEXITCODE -ne 0) { throw 'Gateway recreation failed' }
    }
}
Invoke-VulnCompose -Arguments @('exec', '-T', 'api', 'python', '-c', 'from app.services.scanner_agent_jobs import _merge_edge_target_progress; from app.services.aetheris_severity import choose_cvss_score; print("Scanner integration imports passed")')
Write-Host 'Central scanner integration updated. Confirm live per-IP status using the updated Laptop Scanner.'
