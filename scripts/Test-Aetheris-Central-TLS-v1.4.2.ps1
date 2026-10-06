[CmdletBinding()]
param(
    [string]$ProjectRoot = "",
    [string]$PublicIP = "122.179.140.167"
)

$ErrorActionPreference = "Stop"
$ProgressPreference = "SilentlyContinue"

function Step([string]$m) { Write-Host "`n==== $m ====" -ForegroundColor Cyan }
function Ok([string]$m) { Write-Host "[OK] $m" -ForegroundColor Green }
function Warn([string]$m) { Write-Host "[WARN] $m" -ForegroundColor Yellow }
function Fail([string]$m) { Write-Host "[FAIL] $m" -ForegroundColor Red }

function Invoke-NativeCapture {
    param(
        [Parameter(Mandatory=$true)][string]$FilePath,
        [Parameter(Mandatory=$false)][string[]]$ArgumentList = @()
    )
    $outFile = Join-Path $env:TEMP ("aetheris-out-" + [guid]::NewGuid().ToString("N") + ".txt")
    $errFile = Join-Path $env:TEMP ("aetheris-err-" + [guid]::NewGuid().ToString("N") + ".txt")
    try {
        # Start-Process avoids Windows PowerShell 5.1 converting successful native STDERR
        # (nginx -t writes success messages to STDERR) into a terminating NativeCommandError.
        $quoted = foreach ($a in $ArgumentList) {
            if ($a -match '[\s"]') { '"' + ($a.Replace('"','\"')) + '"' } else { $a }
        }
        $p = Start-Process -FilePath $FilePath -ArgumentList ($quoted -join ' ') -NoNewWindow -Wait -PassThru `
            -RedirectStandardOutput $outFile -RedirectStandardError $errFile
        $lines = @()
        if (Test-Path $outFile) { $lines += @(Get-Content -LiteralPath $outFile -ErrorAction SilentlyContinue) }
        if (Test-Path $errFile) { $lines += @(Get-Content -LiteralPath $errFile -ErrorAction SilentlyContinue) }
        [pscustomobject]@{ ExitCode = [int]$p.ExitCode; Lines = $lines }
    }
    finally {
        Remove-Item -LiteralPath $outFile,$errFile -Force -ErrorAction SilentlyContinue
    }
}

function Show-Lines($result) {
    if ($result -and $result.Lines) { $result.Lines | ForEach-Object { Write-Host $_ } }
}

if (-not $ProjectRoot) {
    $ProjectRoot = (Resolve-Path (Join-Path $PSScriptRoot "..\..")).Path
}
$baseCompose = Join-Path $ProjectRoot "services\gateway\docker-compose.yml"
$httpsCompose = Join-Path $ProjectRoot "deployment\windows-ip-https\docker-compose.gateway-public-https.yml"
if (-not (Test-Path -LiteralPath $baseCompose)) {
    throw "ProjectRoot does not look like the Polaron/Aetheris repository: $ProjectRoot"
}
Set-Location $ProjectRoot

Write-Host "=============================================================================="
Write-Host "Aetheris Central TLS diagnostic v1.4.2"
Write-Host "=============================================================================="
Write-Host "ProjectRoot=$ProjectRoot"
Write-Host "PublicIP=$PublicIP"

Step "Host TCP 443 listeners and owners"
$listen443 = @(Get-NetTCPConnection -State Listen -LocalPort 443 -ErrorAction SilentlyContinue)
if ($listen443.Count) {
    Ok ("TCP 443 is listening on the Windows host ({0} listener(s))." -f $listen443.Count)
    $rows = foreach ($l in $listen443) {
        $proc = Get-CimInstance Win32_Process -Filter ("ProcessId={0}" -f $l.OwningProcess) -ErrorAction SilentlyContinue
        [pscustomobject]@{
            LocalAddress = $l.LocalAddress
            LocalPort = $l.LocalPort
            PID = $l.OwningProcess
            Process = if ($proc) { $proc.Name } else { "<unknown>" }
            Executable = if ($proc) { $proc.ExecutablePath } else { "" }
        }
    }
    $rows | Format-Table -AutoSize
} else {
    Fail "Nothing is listening on Windows TCP 443."
}

Step "Docker containers currently publishing host 443"
$dockerPs = Invoke-NativeCapture -FilePath "docker.exe" -ArgumentList @("ps","--format","{{.ID}}|{{.Names}}|{{.Ports}}")
if ($dockerPs.ExitCode -ne 0) {
    Fail "docker ps failed."
    Show-Lines $dockerPs
    exit 2
}
$host443Containers = @($dockerPs.Lines | Where-Object { $_ -match '(^|[, ])(?:0\.0\.0\.0|\[::\]|127\.0\.0\.1)?:?443->|:443->' })
if ($host443Containers.Count) {
    $host443Containers | ForEach-Object { Write-Host $_ }
    Warn "At least one Docker container currently publishes host TCP 443. Confirm it is the Aetheris gateway."
} else {
    Warn "No Docker container currently publishes host TCP 443. The Windows 443 listener belongs to another host process/service."
}

Step "Aetheris gateway container"
$idsResult = Invoke-NativeCapture -FilePath "docker.exe" -ArgumentList @("ps","--filter","label=com.docker.compose.project=aetheris-gateway","--filter","label=com.docker.compose.service=gateway","-q")
$gateway = if ($idsResult.Lines.Count) { ([string]$idsResult.Lines[0]).Trim() } else { "" }
if (-not $gateway) {
    Fail "No running aetheris-gateway/gateway container was found."
    Write-Host "Start it with BOTH compose files, not the base compose alone."
    exit 2
}
Ok "Gateway container is running: $gateway"
$gatewayPs = Invoke-NativeCapture -FilePath "docker.exe" -ArgumentList @("ps","--filter","id=$gateway","--format","{{.ID}}|{{.Names}}|{{.Status}}|{{.Ports}}")
Show-Lines $gatewayPs
$gatewayPorts = ($gatewayPs.Lines -join " ")
$gatewayPublishes443 = $gatewayPorts -match ':443->443/tcp|0\.0\.0\.0:443->443/tcp|\[::\]:443->443/tcp'
if ($gatewayPublishes443) {
    Ok "The running Aetheris gateway publishes host TCP 443."
} else {
    Fail "The running Aetheris gateway does NOT publish host TCP 443."
    Warn "This usually means it was started only with services/gateway/docker-compose.yml (port 3001) and the public HTTPS overlay was not applied."
}

Step "Gateway bind mounts"
$mounts = Invoke-NativeCapture -FilePath "docker.exe" -ArgumentList @("inspect",$gateway,"--format","{{range .Mounts}}{{println .Source \" -> \" .Destination}}{{end}}")
Show-Lines $mounts
$mountText = $mounts.Lines -join "`n"
if ($mountText -match 'nginx\.gateway\.https\.conf.*->\s*/etc/nginx/conf\.d/default\.conf') {
    Ok "Public HTTPS Nginx config is mounted into the running gateway."
} elseif ($mountText -match 'nginx-gateway\.conf.*->\s*/etc/nginx/conf\.d/default\.conf') {
    Fail "The running gateway is using the HTTP-only/local nginx-gateway.conf, not nginx.gateway.https.conf."
} else {
    Warn "Could not positively identify which default Nginx config is mounted."
}

Step "Nginx configuration"
$nginxTest = Invoke-NativeCapture -FilePath "docker.exe" -ArgumentList @("exec",$gateway,"nginx","-t")
Show-Lines $nginxTest
if ($nginxTest.ExitCode -eq 0) { Ok "nginx -t passed." } else { Fail "nginx -t failed." }

$nginxDump = Invoke-NativeCapture -FilePath "docker.exe" -ArgumentList @("exec",$gateway,"sh","-c","nginx -T 2>&1 | grep -E 'listen .*443|server_name|ssl_certificate|ssl_protocols' | head -100")
Write-Host "`nActive TLS/listen/server_name lines:"
Show-Lines $nginxDump
$nginxTlsText = $nginxDump.Lines -join "`n"
$containerListens443 = $nginxTlsText -match 'listen\s+.*443\s+ssl'
if ($containerListens443) { Ok "Nginx inside the gateway has a TLS 443 server block." } else { Fail "Nginx inside the gateway has no TLS 443 server block." }

Step "Effective compose configuration expected for public HTTPS"
if (Test-Path -LiteralPath $httpsCompose) {
    $composeConfig = Invoke-NativeCapture -FilePath "docker.exe" -ArgumentList @(
        "compose","--project-directory",$ProjectRoot,"--project-name","aetheris-gateway",
        "-f","services/gateway/docker-compose.yml",
        "-f","deployment/windows-ip-https/docker-compose.gateway-public-https.yml",
        "config"
    )
    if ($composeConfig.ExitCode -eq 0) {
        $portLines = @($composeConfig.Lines | Select-String -Pattern 'published:\s*"?(80|443|3001|3002)"?|target:\s*(80|443)' | ForEach-Object { $_.Line })
        if ($portLines.Count) { $portLines | ForEach-Object { Write-Host $_ } }
        if (($composeConfig.Lines -join "`n") -match 'published:\s*["'']?443["'']?') {
            Ok "The public HTTPS compose overlay is configured to publish 443."
        } else {
            Fail "The effective public HTTPS compose configuration does not publish 443."
        }
    } else {
        Fail "Could not render the combined public HTTPS compose configuration."
        Show-Lines $composeConfig
    }
} else {
    Fail "Missing HTTPS compose overlay: $httpsCompose"
}

Step "Certificate path"
$certDir = "/etc/letsencrypt/live/$PublicIP"
if ($containerListens443) {
    $certLs = Invoke-NativeCapture -FilePath "docker.exe" -ArgumentList @("exec",$gateway,"sh","-c","ls -la '$certDir'")
    Show-Lines $certLs
    if ($certLs.ExitCode -eq 0) {
        Ok "Certificate directory for current public IP exists inside the gateway."
    } else {
        Fail "No certificate directory for $PublicIP is mounted at $certDir."
    }
} else {
    Warn "Skipping certificate path test because the running gateway is not using a TLS 443 config."
}

Step "Local TLS handshake inside the gateway"
if ($containerListens443) {
    $probe = Invoke-NativeCapture -FilePath "docker.exe" -ArgumentList @("exec",$gateway,"sh","-c","wget -S -T 8 -O /dev/null --no-check-certificate https://127.0.0.1/api/health 2>&1")
    Show-Lines $probe
    if ($probe.ExitCode -eq 0) { Ok "Local TLS handshake completed inside the gateway." } else { Fail "Local TLS handshake failed inside the gateway." }
} else {
    Warn "Skipping local TLS handshake because Nginx is not listening on 443 inside this gateway container."
}

Step "Recommended correction"
if (-not $gatewayPublishes443 -or -not $containerListens443) {
    Write-Host "The current gateway was started without the public HTTPS overlay."
    Write-Host "First make sure no unrelated process/container owns host port 443, then run:"
    Write-Host ""
    Write-Host "  docker compose --project-directory `"$ProjectRoot`" --project-name aetheris-gateway ``"
    Write-Host "    -f services/gateway/docker-compose.yml ``"
    Write-Host "    -f deployment/windows-ip-https/docker-compose.gateway-public-https.yml ``"
    Write-Host "    up -d --force-recreate gateway"
    Write-Host ""
    Write-Host "If Docker reports port 443 already allocated, identify the PID/container shown above before stopping anything."
}

Step "Recent gateway logs"
$logs = Invoke-NativeCapture -FilePath "docker.exe" -ArgumentList @("logs","--tail","120",$gateway)
Show-Lines $logs

Write-Host "`n=============================================================================="
if ($gatewayPublishes443 -and $containerListens443 -and $nginxTest.ExitCode -eq 0) {
    Ok "Gateway is at least running the HTTPS overlay. Continue with certificate and local TLS checks above."
    exit 0
}
Fail "Aetheris public HTTPS is not active on the running gateway. Correct the port-443 owner/compose overlay first."
exit 3
