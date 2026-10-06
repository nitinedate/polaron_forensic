param(
    [string]$EnvFile = (Join-Path (Split-Path -Parent $PSScriptRoot) ".env")
)

$ErrorActionPreference = "Stop"
$root = Split-Path -Parent $PSScriptRoot
$template = Join-Path $root ".env.example"

if (-not (Test-Path $EnvFile)) {
    if (-not (Test-Path $template)) { throw "Missing .env and .env.example" }
    Copy-Item $template $EnvFile
    Write-Host "Created $EnvFile from .env.example. Fill CENTRAL_API_URL, TENANT_SLUG and AGENT_TOKEN before starting." -ForegroundColor Yellow
}

$settings = [ordered]@{
    'AGENT_VERSION' = '1.2.20'
    'PORT_PROFILE' = 'fast'
    'MAX_CONCURRENT_SCAN_JOBS' = '1'
    'SCAN_IP_PARALLELISM' = 'auto'
    'SCAN_IP_MAX_PARALLELISM' = '10'
    'GVM_GLOBAL_MAX_HOSTS' = '10'
    'GVM_MAX_HOSTS' = '1'
    'GVM_MAX_CHECKS' = '6'
    'SKIP_UNREACHABLE_TARGETS' = 'true'
    'REACHABILITY_TIMEOUT_SEC' = '0.35'
    'PORT_DISCOVERY_TIMEOUT_SEC' = '0.35'
    'PORT_DISCOVERY_WORKERS_PER_HOST' = '12'
    'REACHABILITY_UNKNOWN_POLICY' = 'scan'
    'PLUGINS_TIMEOUT_SEC' = '900'
    'SCANNER_PLUGINS_TIMEOUT_SEC' = '1800'
    'GVM_OPTIMIZE_TEST' = 'yes'
    'GVM_SAFE_CHECKS' = 'yes'
    'GVM_EXPAND_VHOSTS' = 'no'
    'GVM_TEST_EMPTY_VHOST' = 'no'
    'GVM_CHECKS_READ_TIMEOUT' = '8'
    'GVM_TIMEOUT_RETRY' = '1'
    'GVM_OPEN_SOCK_MAX_ATTEMPTS' = '2'
    'MAX_IP_SCAN_RUNTIME_SEC' = '3600'
    'MAX_SCAN_RUNTIME_SEC' = '7200'
    'HIGH_PROGRESS_WARN_SEC' = '300'
}

$lines = [System.Collections.Generic.List[string]]::new()
Get-Content -LiteralPath $EnvFile | ForEach-Object { [void]$lines.Add($_) }
foreach ($key in $settings.Keys) {
    $value = $settings[$key]
    $matched = $false
    for ($i = 0; $i -lt $lines.Count; $i++) {
        if ($lines[$i] -match ('^\s*' + [regex]::Escape($key) + '\s*=')) {
            $lines[$i] = "$key=$value"
            $matched = $true
            break
        }
    }
    if (-not $matched) { [void]$lines.Add("$key=$value") }
}
Set-Content -LiteralPath $EnvFile -Value $lines -Encoding UTF8
Write-Host "Applied vulnerability Fast profile to $EnvFile without changing credentials." -ForegroundColor Green
