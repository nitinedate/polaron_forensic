$ErrorActionPreference = 'Stop'
$root = Split-Path -Parent $MyInvocation.MyCommand.Path
$envFile = Join-Path $root '.env'
if (-not (Test-Path -LiteralPath $envFile)) {
    Copy-Item -LiteralPath (Join-Path $root '.env.example') -Destination $envFile
}

$updates = [ordered]@{
    'MAX_CONCURRENT_SCAN_JOBS' = '1'
    'SCAN_IP_PARALLELISM' = 'auto'
    'SCAN_IP_MAX_PARALLELISM' = '6'
    'SCAN_SLO_MIN_HOSTS_PER_HOUR' = '15'
    'SCAN_SLO_HOSTS_PER_HOUR' = '18'
    'SCAN_EXPECTED_HOST_MINUTES' = '20'
    'GVM_MAX_HOSTS' = '1'
    'GVM_MAX_CHECKS' = '8'
    'PORT_PROFILE' = 'fast'
    'PORT_DISCOVERY_ENABLED' = 'true'
    'GVM_OPTIMIZE_TEST' = 'yes'
    'SKIP_UNREACHABLE_TARGETS' = 'false'
    'REACHABILITY_TIMEOUT_SEC' = '0.5'
    'REACHABILITY_WORKERS' = '10'
    'IP_SCAN_LOG_DIR' = '/app/logs/ip'
    'AGENT_VERSION' = '1.3.5'
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
New-Item -ItemType Directory -Force -Path (Join-Path $root 'logs\ip') | Out-Null
Write-Host 'LaptopScanner v1.3.5 throughput settings applied.' -ForegroundColor Green
Write-Host 'Rebuild/recreate the scanner stack with your normal Start-Laptop.cmd workflow.'
