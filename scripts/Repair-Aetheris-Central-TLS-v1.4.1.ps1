[CmdletBinding()]
param(
    [string]$ProjectRoot = "",
    [string]$PublicIP = "122.179.140.167",
    [string]$LanIP = "192.168.1.16",
    [string]$Email = "",
    [switch]$SelfSigned,
    [switch]$SkipCertificateIssue
)

$ErrorActionPreference = "Stop"
$ProgressPreference = "SilentlyContinue"
$env:COMPOSE_IGNORE_ORPHANS = "true"
$env:COMPOSE_REMOVE_ORPHANS = "false"
$env:COMPOSE_PROGRESS = "plain"
$env:DOCKER_CLI_HINTS = "false"

function Step([string]$m) { Write-Host "`n==== $m ====" -ForegroundColor Cyan }
function Ok([string]$m) { Write-Host "[OK] $m" -ForegroundColor Green }
function Warn([string]$m) { Write-Host "[WARN] $m" -ForegroundColor Yellow }

function Assert-Admin {
    $id = [Security.Principal.WindowsIdentity]::GetCurrent()
    $p = New-Object Security.Principal.WindowsPrincipal($id)
    if (-not $p.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
        throw "Run PowerShell as Administrator."
    }
}

function ComposeArgs([string]$root) {
    return @(
        "compose",
        "--project-directory", $root,
        "--project-name", "aetheris-gateway",
        "-f", "services/gateway/docker-compose.yml",
        "-f", "deployment/windows-ip-https/docker-compose.gateway-public-https.yml"
    )
}

Assert-Admin
if (-not $ProjectRoot) {
    $ProjectRoot = (Resolve-Path (Join-Path $PSScriptRoot "..\..")).Path
}
$baseCompose = Join-Path $ProjectRoot "services\gateway\docker-compose.yml"
$publicCompose = Join-Path $ProjectRoot "deployment\windows-ip-https\docker-compose.gateway-public-https.yml"
$nginxPath = Join-Path $ProjectRoot "deployment\windows-ip-https\nginx.gateway.https.conf"
$setupScript = Join-Path $ProjectRoot "scripts\setup-public-https.ps1"
foreach ($p in @($baseCompose,$publicCompose,$nginxPath,$setupScript)) {
    if (-not (Test-Path -LiteralPath $p)) { throw "Required file missing: $p" }
}
Set-Location $ProjectRoot

Write-Host "=============================================================================="
Write-Host "Aetheris Central TLS repair v1.4.1"
Write-Host "=============================================================================="
Write-Host "ProjectRoot=$ProjectRoot"
Write-Host "PublicIP=$PublicIP"
Write-Host "LanIP=$LanIP"

Step "Back up current public HTTPS Nginx configuration"
$stamp = Get-Date -Format "yyyyMMdd-HHmmss"
$backup = "$nginxPath.v141-$stamp.bak"
Copy-Item -LiteralPath $nginxPath -Destination $backup -Force
Ok "Backup created: $backup"

Step "Rewrite Nginx public TLS endpoint for the current IP"
$txt = [IO.File]::ReadAllText($nginxPath)
# Replace any historical IPv4 server_name/certificate directory with the current public IP.
$txt = [regex]::Replace($txt, 'server_name\s+[0-9.]+(?:\s+_)?\s*;', "server_name $PublicIP _;")
$txt = [regex]::Replace($txt, '/etc/letsencrypt/live/[0-9.]+/', "/etc/letsencrypt/live/$PublicIP/")
# Make this listener the explicit default so clients connecting to a raw IP/no SNI get a certificate.
$txt = [regex]::Replace($txt, 'listen\s+443\s+ssl(?:\s+default_server)?\s*;', 'listen 443 ssl default_server;')
$txt = [regex]::Replace($txt, 'listen\s+\[::\]:443\s+ssl(?:\s+default_server)?\s*;', 'listen [::]:443 ssl default_server;')
if ($txt -notmatch 'ssl_protocols\s+TLSv1\.2\s+TLSv1\.3') {
    $txt = $txt -replace '(ssl_certificate_key\s+[^;]+;)', "$1`r`n    ssl_protocols TLSv1.2 TLSv1.3;"
}
# Keep compatibility broad enough for Windows/OpenSSL clients while excluding obsolete suites.
if ($txt -notmatch 'ssl_ciphers\s+') {
    $txt = $txt -replace '(ssl_protocols\s+TLSv1\.2\s+TLSv1\.3;)', "$1`r`n    ssl_ciphers HIGH:!aNULL:!MD5;`r`n    ssl_prefer_server_ciphers off;"
}
[IO.File]::WriteAllText($nginxPath, $txt, [Text.UTF8Encoding]::new($false))
Ok "Nginx HTTPS config now uses PublicIP=$PublicIP and an explicit default TLS listener."

Step "Windows firewall"
foreach ($port in @(80,443)) {
    $name = "Aetheris Public HTTPS $port"
    $existing = Get-NetFirewallRule -DisplayName $name -ErrorAction SilentlyContinue
    if ($existing) {
        $existing | Set-NetFirewallRule -Enabled True -Direction Inbound -Action Allow -Profile Any | Out-Null
    } else {
        New-NetFirewallRule -DisplayName $name -Direction Inbound -Action Allow -Protocol TCP -LocalPort $port -Profile Any | Out-Null
    }
    Ok "TCP $port allowed by Windows Firewall rule '$name'."
}

Step "Certificate for current public IP"
if ($SkipCertificateIssue) {
    Warn "Skipping certificate issuance by request. A valid certificate must already exist for $PublicIP."
} elseif ($SelfSigned) {
    Warn "Creating a self-signed IP certificate. This is only for diagnostics unless the client trusts this certificate/CA."
    & powershell.exe -NoProfile -ExecutionPolicy Bypass -File $setupScript -ProjectRoot $ProjectRoot -PublicIP $PublicIP -LanIP $LanIP -SelfSigned -ForceRecreate
    if ($LASTEXITCODE -ne 0) { throw "setup-public-https.ps1 self-signed setup failed (exit $LASTEXITCODE)." }
} elseif ($Email) {
    Write-Host "Requesting/refreshing the trusted short-lived IP certificate for $PublicIP..."
    & powershell.exe -NoProfile -ExecutionPolicy Bypass -File $setupScript -ProjectRoot $ProjectRoot -PublicIP $PublicIP -LanIP $LanIP -Email $Email -ForceRecreate
    if ($LASTEXITCODE -ne 0) { throw "setup-public-https.ps1 certificate setup failed (exit $LASTEXITCODE)." }
} else {
    Warn "No -Email or -SelfSigned was supplied. The repair will use the existing certificate volume if present."
}

Step "Recreate HTTPS gateway"
$c = ComposeArgs $ProjectRoot
& docker.exe @($c + @("up","-d","--force-recreate","gateway"))
if ($LASTEXITCODE -ne 0) { throw "Could not recreate aetheris-gateway." }
Start-Sleep -Seconds 5

$ids = @(& docker.exe ps --filter "label=com.docker.compose.project=aetheris-gateway" --filter "label=com.docker.compose.service=gateway" -q)
$gateway = if ($ids.Count) { ([string]$ids[0]).Trim() } else { "" }
if (-not $gateway) { throw "Gateway container did not start. Run docker compose logs gateway." }
Ok "Gateway running: $gateway"

Step "Validate Nginx"
& docker.exe exec $gateway nginx -t
if ($LASTEXITCODE -ne 0) { throw "nginx -t failed after repair." }
Ok "nginx -t passed."

Step "Verify current-IP certificate directory"
$certDir = "/etc/letsencrypt/live/$PublicIP"
& docker.exe exec $gateway sh -c "ls -la '$certDir'"
if ($LASTEXITCODE -ne 0) {
    throw "The gateway still has no certificate mounted for $PublicIP at $certDir. Re-run with -Email <address> for a trusted certificate or -SelfSigned for a temporary diagnostic certificate."
}
Ok "Certificate directory exists for $PublicIP."

Step "Verify TLS locally without SNI"
& docker.exe exec $gateway sh -c "wget -S -T 10 -O /dev/null --no-check-certificate https://127.0.0.1/api/health 2>&1"
if ($LASTEXITCODE -ne 0) {
    throw "Local TLS handshake still fails inside the gateway. Review: docker logs $gateway --tail 200"
}
Ok "Local no-SNI/IP-style TLS handshake succeeds."

Step "Host listener"
$listen = @(Get-NetTCPConnection -State Listen -LocalPort 443 -ErrorAction SilentlyContinue)
if (-not $listen.Count) { throw "Windows host still has no listener on TCP 443." }
Ok "Windows host is listening on TCP 443."

Write-Host "`n=============================================================================="
Ok "Central TLS repair completed."
Write-Host "Router/NAT must forward WAN ${PublicIP}:443 to this Windows host ${LanIP}:443."
Write-Host "Router/NAT must forward WAN ${PublicIP}:80 to this Windows host ${LanIP}:80 for certificate issuance/renewal."
Write-Host ""
Write-Host "Now, from the CLIENT laptop, rerun:"
Write-Host "  powershell -NoProfile -ExecutionPolicy Bypass -File .\Test-Docker-TLS-v1.4.0.ps1"
Write-Host ""
Write-Host "If you used -SelfSigned, VERIFY_TLS=true will correctly reject it unless the client trusts that certificate/CA."
