# Issues a Let's Encrypt certificate for a public domain and points aetheris-gateway at it.
param(
    [string]$Domain = "future-softtech.co.in",
    [string]$Email = "ndate1976@gmail.com",
    [string]$LanIP = "192.168.1.9",
    [string]$PublicIP = "122.179.140.167"
)

$ErrorActionPreference = "Stop"
$env:COMPOSE_IGNORE_ORPHANS = "true"
$env:COMPOSE_REMOVE_ORPHANS = "false"
$env:COMPOSE_PROGRESS = "plain"
$env:DOCKER_CLI_HINTS = "false"

$identity = [Security.Principal.WindowsIdentity]::GetCurrent()
$principal = New-Object Security.Principal.WindowsPrincipal($identity)
if (-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    throw "Run PowerShell as Administrator, then re-run this script."
}

$Root = (Resolve-Path (Join-Path $PSScriptRoot "..")).Path
Set-Location $Root
$Domain = $Domain.Trim().TrimEnd('.')
if (-not $Domain -or -not $Email) { throw "Domain and Email are required." }

function Invoke-Docker {
    param([Parameter(Mandatory = $true)][string[]]$ArgumentList, [string]$FailureMessage = "Docker command failed")
    $docker = (Get-Command docker.exe -ErrorAction SilentlyContinue)
    if (-not $docker) { $docker = Get-Command docker -ErrorAction SilentlyContinue }
    if (-not $docker) { throw "Docker CLI was not found." }
    $quoted = foreach ($arg in $ArgumentList) {
        if ($arg -match '[\s"]') { '"' + ($arg.Replace('"', '\"')) + '"' } else { $arg }
    }
    $out = Join-Path $env:TEMP "aetheris-docker-out.txt"
    $err = Join-Path $env:TEMP "aetheris-docker-err.txt"
    $p = Start-Process -FilePath $docker.Source -ArgumentList ($quoted -join ' ') -NoNewWindow -Wait -PassThru -RedirectStandardOutput $out -RedirectStandardError $err
    $log = @()
    if (Test-Path $out) { $log += @(Get-Content -LiteralPath $out -ErrorAction SilentlyContinue) }
    if (Test-Path $err) { $log += @(Get-Content -LiteralPath $err -ErrorAction SilentlyContinue) }
    if ([int]$p.ExitCode -ne 0) {
        $log | ForEach-Object { Write-Host $_ }
        throw ("{0} (exit {1})" -f $FailureMessage, $p.ExitCode)
    }
}

$compose = @(
    "compose", "--project-directory", $Root, "--project-name", "aetheris-gateway",
    "-f", "services/gateway/docker-compose.yml",
    "-f", "deployment/windows-ip-https/docker-compose.gateway-public-https.yml"
)

$nginxPath = Join-Path $Root "deployment\windows-ip-https\nginx.gateway.https.conf"
if (-not (Test-Path -LiteralPath $nginxPath)) { throw "Missing $nginxPath" }
$nginx = [System.IO.File]::ReadAllText($nginxPath)
$nginx = [regex]::Replace($nginx, '(?m)^(\s*server_name\s+)(?!_;)\S+(?:\s+_)?\s*;', { param($m) $m.Groups[1].Value + $Domain + ' _;' })
$nginx = [regex]::Replace($nginx, '/etc/letsencrypt/live/[^/]+/', ("/etc/letsencrypt/live/{0}/" -f $Domain))
[System.IO.File]::WriteAllText($nginxPath, $nginx)
Write-Host "Nginx certificate path set to $Domain"

$composePath = Join-Path $Root "deployment\windows-ip-https\docker-compose.gateway-public-https.yml"
if (Test-Path -LiteralPath $composePath) {
    $composeText = [System.IO.File]::ReadAllText($composePath)
    $stripped = [regex]::Replace($composeText, '(?m)^\s*-\s*"3002:80"\s*\r?\n', '')
    if ($stripped -ne $composeText) {
        [System.IO.File]::WriteAllText($composePath, $stripped)
        Write-Host "Removed gateway port 3002"
    }
}

Write-Host "Stopping gateway so port 80 is free for Let's Encrypt..."
try { Invoke-Docker -ArgumentList ($compose + @("stop", "gateway")) } catch { Write-Host $_ }

Write-Host "Starting ACME bootstrap on port 80..."
Invoke-Docker -ArgumentList ($compose + @("--profile", "acme-bootstrap", "up", "-d", "acme-bootstrap")) -FailureMessage "Could not start acme-bootstrap. Forward TCP 80 from $PublicIP to ${LanIP}:80."

try {
    Write-Host "Requesting Let's Encrypt certificate for $Domain ..."
    Invoke-Docker -ArgumentList ($compose + @(
        "--profile", "certbot", "run", "--rm", "certbot",
        "certonly", "--webroot", "--webroot-path", "/var/www/certbot",
        "-d", $Domain, "--cert-name", $Domain,
        "--email", $Email, "--agree-tos", "--non-interactive"
    )) -FailureMessage "Let's Encrypt certificate request failed"
    Write-Host "Certificate issued for $Domain"
}
finally {
    try { Invoke-Docker -ArgumentList ($compose + @("--profile", "acme-bootstrap", "rm", "-sf", "acme-bootstrap")) } catch { }
}

foreach ($rel in @(".env", "services\forensic\.env", "services\vuln\.env", "services\mobile-extract\.env")) {
    $path = Join-Path $Root $rel
    if (-not (Test-Path -LiteralPath $path)) { continue }
    $raw = [System.IO.File]::ReadAllText($path)
    $url = "https://$Domain"
    if ($raw -match '(?m)^APP_BASE_URL=') {
        $raw = [regex]::Replace($raw, '(?m)^APP_BASE_URL=.*$', "APP_BASE_URL=$url")
    } else {
        $raw = $raw.TrimEnd() + "`r`nAPP_BASE_URL=$url`r`n"
    }
    [System.IO.File]::WriteAllText($path, $raw)
}

Write-Host "Starting gateway with the trusted certificate..."
Invoke-Docker -ArgumentList ($compose + @("up", "-d", "--force-recreate", "gateway")) -FailureMessage "Gateway start failed"
Write-Host "Done. Open https://$Domain"