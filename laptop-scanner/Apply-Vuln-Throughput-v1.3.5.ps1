$ErrorActionPreference = 'Stop'
$root = Split-Path -Parent $MyInvocation.MyCommand.Path
$envFile = Join-Path $root '.env'
$example = Join-Path $root '.env.example'

if (-not (Test-Path -LiteralPath $envFile)) {
    Copy-Item -LiteralPath $example -Destination $envFile
} else {
    Copy-Item -LiteralPath $envFile -Destination ($envFile + '.pre-v1.3.5-' + (Get-Date -Format 'yyyyMMdd-HHmmss'))
}

$updates = [ordered]@{
    'AGENT_VERSION' = '1.3.5'
    'MAX_CONCURRENT_SCAN_JOBS' = '1'
    'SCAN_IP_PARALLELISM' = 'auto'
    'SCAN_IP_MAX_PARALLELISM' = '6'
    'SCAN_SLO_MIN_HOSTS_PER_HOUR' = '15'
    'SCAN_SLO_HOSTS_PER_HOUR' = '18'
    'SCAN_EXPECTED_HOST_MINUTES' = '20'
    'PORT_PROFILE' = 'fast'
    'PORT_DISCOVERY_ENABLED' = 'true'
    'PORT_DISCOVERY_TIMEOUT_SEC' = '0.25'
    'PORT_DISCOVERY_WORKERS' = '32'
    'GVM_MAX_HOSTS' = '1'
    'GVM_MAX_CHECKS' = '8'
    'GVM_OPTIMIZE_TEST' = 'yes'
    'GVM_SAFE_CHECKS' = 'yes'
    'SKIP_UNREACHABLE_TARGETS' = 'false'
    'MAX_SCAN_RUNTIME_SEC' = '0'
}

$text = Get-Content -LiteralPath $envFile -Raw
foreach ($key in $updates.Keys) {
    $value = $updates[$key]
    $pattern = '(?m)^' + [regex]::Escape($key) + '=.*$'
    if ([regex]::IsMatch($text, $pattern)) {
        $text = [regex]::Replace($text, $pattern, "$key=$value")
    } else {
        $text = $text.TrimEnd() + "`r`n$key=$value`r`n"
    }
}
Set-Content -LiteralPath $envFile -Value $text -Encoding UTF8

Push-Location $root
try {
    Write-Host 'Rebuilding scanner-agent v1.3.5...' -ForegroundColor Cyan
    docker compose build --no-cache scanner-agent
    docker compose up -d --force-recreate scanner-agent
    Write-Host ''
    Write-Host 'v1.3.5 15-18 IP/hour profile applied.' -ForegroundColor Green
    Write-Host 'Watch: docker compose logs -f scanner-agent'
} finally {
    Pop-Location
}
