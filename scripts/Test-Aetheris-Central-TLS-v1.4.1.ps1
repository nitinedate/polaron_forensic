[CmdletBinding()]
param(
    [string]$ProjectRoot = "",
    [string]$PublicIP = "122.179.140.167"
)

$ErrorActionPreference = "Stop"

function Step([string]$m) { Write-Host "`n==== $m ====" -ForegroundColor Cyan }
function Ok([string]$m) { Write-Host "[OK] $m" -ForegroundColor Green }
function Warn([string]$m) { Write-Host "[WARN] $m" -ForegroundColor Yellow }
function Fail([string]$m) { Write-Host "[FAIL] $m" -ForegroundColor Red }

if (-not $ProjectRoot) {
    $ProjectRoot = (Resolve-Path (Join-Path $PSScriptRoot "..\..")).Path
}
if (-not (Test-Path -LiteralPath (Join-Path $ProjectRoot "services\gateway\docker-compose.yml"))) {
    throw "ProjectRoot does not look like the Polaron/Aetheris repository: $ProjectRoot"
}
Set-Location $ProjectRoot

Write-Host "=============================================================================="
Write-Host "Aetheris Central TLS diagnostic v1.4.1"
Write-Host "=============================================================================="
Write-Host "ProjectRoot=$ProjectRoot"
Write-Host "PublicIP=$PublicIP"

Step "Host TCP listeners"
$listen443 = @(Get-NetTCPConnection -State Listen -LocalPort 443 -ErrorAction SilentlyContinue)
if ($listen443.Count) {
    Ok ("TCP 443 is listening on the Windows host ({0} listener(s))." -f $listen443.Count)
    $listen443 | Select-Object LocalAddress,LocalPort,OwningProcess | Format-Table -AutoSize
} else {
    Fail "Nothing is listening on Windows TCP 443. The gateway cannot serve HTTPS."
}

Step "Docker gateway container"
$ids = @(& docker.exe ps --filter "label=com.docker.compose.project=aetheris-gateway" --filter "label=com.docker.compose.service=gateway" -q 2>$null)
$gateway = if ($ids.Count) { ([string]$ids[0]).Trim() } else { "" }
if (-not $gateway) {
    Fail "No running aetheris-gateway/gateway container was found."
    Write-Host "Run the repair script to recreate the public HTTPS gateway."
    exit 2
}
Ok "Gateway container is running: $gateway"
& docker.exe ps --filter "id=$gateway" --format "table {{.ID}}\t{{.Names}}\t{{.Status}}\t{{.Ports}}"

Step "Nginx configuration"
$nginxTest = @(& docker.exe exec $gateway nginx -t 2>&1)
$nginxRc = $LASTEXITCODE
$nginxTest | ForEach-Object { Write-Host $_ }
if ($nginxRc -eq 0) { Ok "nginx -t passed." } else { Fail "nginx -t failed." }

Write-Host "`nActive TLS/listen/server_name lines:"
& docker.exe exec $gateway sh -c "nginx -T 2>&1 | grep -E 'listen .*443|server_name|ssl_certificate|ssl_protocols' | head -80"

Step "Certificate path"
$certDir = "/etc/letsencrypt/live/$PublicIP"
$certLs = @(& docker.exe exec $gateway sh -c "ls -la '$certDir' 2>&1")
$certRc = $LASTEXITCODE
$certLs | ForEach-Object { Write-Host $_ }
if ($certRc -eq 0) {
    Ok "Certificate directory for current public IP exists inside the gateway."
} else {
    Fail "No certificate directory for $PublicIP is mounted at $certDir."
    Warn "If the deployed certificate is for an older public IP, the gateway must be reissued/reconfigured."
}

Step "No-SNI/local TLS handshake inside gateway"
# BusyBox wget uses the container's TLS stack. --no-check-certificate disables trust
# only for this diagnostic so we can prove that the server can actually complete TLS.
$probe = @(& docker.exe exec $gateway sh -c "wget -S -T 8 -O /dev/null --no-check-certificate https://127.0.0.1/api/health 2>&1")
$probeRc = $LASTEXITCODE
$probe | ForEach-Object { Write-Host $_ }
if ($probeRc -eq 0) {
    Ok "Local TLS handshake completed inside the gateway."
} else {
    Fail "Local TLS handshake failed inside the gateway. This is a central TLS configuration/certificate problem."
}

Step "Recent gateway logs"
& docker.exe logs --tail 120 $gateway 2>&1

Write-Host "`n=============================================================================="
if ($listen443.Count -and $gateway -and $nginxRc -eq 0 -and $certRc -eq 0 -and $probeRc -eq 0) {
    Ok "Central TLS listener looks internally healthy. If the client still fails, verify router 443 DNAT targets THIS Windows host and no router/ISP TLS proxy intercepts 443."
    exit 0
}
Fail "Central HTTPS is not internally healthy. Run Repair-Aetheris-Central-TLS-v1.4.1.ps1."
exit 3
