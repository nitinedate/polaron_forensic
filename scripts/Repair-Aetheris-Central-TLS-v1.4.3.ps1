[CmdletBinding()]
param(
    [string]$ProjectRoot = "",
    [string]$PublicIP = "122.179.140.167",
    [string]$LanIP = "192.168.1.16",
    [string]$Email = "",
    [switch]$SelfSigned,
    [switch]$SkipCertificateIssue,
    [switch]$AllowExistingHost443Owner
)

$ErrorActionPreference = "Stop"
$ProgressPreference = "SilentlyContinue"
$env:COMPOSE_IGNORE_ORPHANS = "true"
$env:COMPOSE_REMOVE_ORPHANS = "false"
$env:COMPOSE_PROGRESS = "plain"
$env:DOCKER_CLI_HINTS = "false"

function Step([string]$Message) { Write-Host "`n==== $Message ====" -ForegroundColor Cyan }
function Ok([string]$Message) { Write-Host "[OK] $Message" -ForegroundColor Green }
function Warn([string]$Message) { Write-Host "[WARN] $Message" -ForegroundColor Yellow }

function Invoke-NativeCapture {
    param(
        [Parameter(Mandatory = $true)][string]$FilePath,
        [string[]]$ArgumentList = @()
    )

    $oldPreference = $ErrorActionPreference
    $raw = @()
    $exitCode = 9009
    try {
        $ErrorActionPreference = "Continue"
        $global:LASTEXITCODE = 0
        $raw = @(& $FilePath @ArgumentList 2>&1)
        $exitCode = [int]$LASTEXITCODE
    }
    catch {
        $raw = @($_.Exception.Message)
        $exitCode = 9009
    }
    finally {
        $ErrorActionPreference = $oldPreference
    }

    return [pscustomobject]@{
        ExitCode = $exitCode
        Lines = @($raw | ForEach-Object { [string]$_ })
    }
}

function Show-Lines($Result) {
    if ($null -ne $Result -and $null -ne $Result.Lines) {
        $Result.Lines | ForEach-Object { Write-Host $_ }
    }
}

function Assert-Admin {
    $identity = [Security.Principal.WindowsIdentity]::GetCurrent()
    $principal = New-Object Security.Principal.WindowsPrincipal($identity)
    if (-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
        throw "Run PowerShell as Administrator."
    }
}

Assert-Admin

if ([string]::IsNullOrWhiteSpace($ProjectRoot)) {
    $ProjectRoot = (Resolve-Path (Join-Path $PSScriptRoot "..\..")).Path
}

$baseCompose = Join-Path $ProjectRoot "services\gateway\docker-compose.yml"
$publicCompose = Join-Path $ProjectRoot "deployment\windows-ip-https\docker-compose.gateway-public-https.yml"
$nginxPath = Join-Path $ProjectRoot "deployment\windows-ip-https\nginx.gateway.https.conf"
$setupScript = Join-Path $ProjectRoot "scripts\setup-public-https.ps1"

foreach ($requiredPath in @($baseCompose, $publicCompose, $nginxPath, $setupScript)) {
    if (-not (Test-Path -LiteralPath $requiredPath)) {
        throw "Required file missing: $requiredPath"
    }
}

Set-Location $ProjectRoot

Write-Host "=============================================================================="
Write-Host "Aetheris Central TLS repair v1.4.3"
Write-Host "=============================================================================="
Write-Host "ProjectRoot=$ProjectRoot"
Write-Host "PublicIP=$PublicIP"
Write-Host "LanIP=$LanIP"

Step "Preflight: current Docker port 443 owners"
$dockerPs = Invoke-NativeCapture -FilePath "docker.exe" -ArgumentList @("ps", "--format", "{{.ID}}|{{.Names}}|{{.Ports}}")
if ($dockerPs.ExitCode -ne 0) {
    Show-Lines $dockerPs
    throw "docker ps failed. Start Docker Desktop/Linux engine first."
}
$docker443 = @($dockerPs.Lines | Where-Object { $_ -match ':443->' })
if ($docker443.Count -gt 0) {
    $docker443 | ForEach-Object { Write-Host $_ }
}
else {
    Write-Host "No Docker container currently publishes host 443."
}

$currentGatewayIds = Invoke-NativeCapture -FilePath "docker.exe" -ArgumentList @(
    "ps",
    "--filter", "label=com.docker.compose.project=aetheris-gateway",
    "--filter", "label=com.docker.compose.service=gateway",
    "-q"
)
$currentGateway = if ($currentGatewayIds.Lines.Count -gt 0) { ([string]$currentGatewayIds.Lines[0]).Trim() } else { "" }
$otherDocker443 = @($docker443 | Where-Object {
    if ([string]::IsNullOrWhiteSpace($currentGateway)) { return $true }
    return ($_ -notmatch [regex]::Escape($currentGateway.Substring(0, [Math]::Min(12, $currentGateway.Length)))) -and ($_ -notmatch 'aetheris-gateway-gateway')
})
if ($otherDocker443.Count -gt 0 -and -not $AllowExistingHost443Owner) {
    throw "Another Docker container already publishes host 443. Stop or reconfigure only that identified container before repair."
}

Step "Preflight: Windows host TCP 443 owners"
$listeners443 = @(Get-NetTCPConnection -State Listen -LocalPort 443 -ErrorAction SilentlyContinue)
if ($listeners443.Count -gt 0) {
    foreach ($listener in $listeners443) {
        $proc = Get-CimInstance Win32_Process -Filter ("ProcessId={0}" -f $listener.OwningProcess) -ErrorAction SilentlyContinue
        $procName = if ($null -ne $proc) { [string]$proc.Name } else { "<unknown>" }
        $procPath = if ($null -ne $proc) { [string]$proc.ExecutablePath } else { "" }
        Write-Host ("{0}:443 PID={1} Process={2} Path={3}" -f $listener.LocalAddress, $listener.OwningProcess, $procName, $procPath)
    }

    # Docker Desktop's backend may own a listener on behalf of published container ports.
    # If no Docker container owns 443, an existing Windows listener will block the gateway.
    if ($docker443.Count -eq 0 -and -not $AllowExistingHost443Owner) {
        throw "Windows TCP 443 is already owned by a non-Docker-published listener. Do not kill it blindly; identify/reconfigure it first, or explicitly rerun with -AllowExistingHost443Owner only when you know it will not block Docker."
    }
}

Step "Back up and update public HTTPS Nginx configuration"
$timestamp = Get-Date -Format "yyyyMMdd-HHmmss"
$backupPath = "$nginxPath.v143-$timestamp.bak"
Copy-Item -LiteralPath $nginxPath -Destination $backupPath -Force

$nginxText = [IO.File]::ReadAllText($nginxPath)
$nginxText = [regex]::Replace($nginxText, 'server_name\s+[0-9.]+(?:\s+_)?\s*;', ("server_name {0} _;" -f $PublicIP))
$nginxText = [regex]::Replace($nginxText, '/etc/letsencrypt/live/[0-9.]+/', ("/etc/letsencrypt/live/{0}/" -f $PublicIP))
$nginxText = [regex]::Replace($nginxText, 'listen\s+443\s+ssl(?:\s+default_server)?\s*;', 'listen 443 ssl default_server;')
$nginxText = [regex]::Replace($nginxText, 'listen\s+\[::\]:443\s+ssl(?:\s+default_server)?\s*;', 'listen [::]:443 ssl default_server;')
if ($nginxText -notmatch 'ssl_protocols\s+TLSv1\.2\s+TLSv1\.3') {
    $replacement = '$1' + [Environment]::NewLine + '    ssl_protocols TLSv1.2 TLSv1.3;'
    $nginxText = $nginxText -replace '(ssl_certificate_key\s+[^;]+;)', $replacement
}
$utf8NoBom = New-Object System.Text.UTF8Encoding -ArgumentList $false
[IO.File]::WriteAllText($nginxPath, $nginxText, $utf8NoBom)
Ok "Updated $nginxPath for $PublicIP"
Ok "Backup created: $backupPath"

Step "Windows firewall"
foreach ($port in @(80, 443)) {
    $displayName = "Aetheris Public HTTPS $port"
    $rule = Get-NetFirewallRule -DisplayName $displayName -ErrorAction SilentlyContinue
    if ($null -ne $rule) {
        $rule | Set-NetFirewallRule -Enabled True -Direction Inbound -Action Allow -Profile Any | Out-Null
    }
    else {
        New-NetFirewallRule -DisplayName $displayName -Direction Inbound -Action Allow -Protocol TCP -LocalPort $port -Profile Any | Out-Null
    }
    Ok "TCP $port allowed by Windows firewall rule '$displayName'."
}

Step "Certificate"
if ($SkipCertificateIssue) {
    Warn "Using the existing certificate volume. A certificate for $PublicIP must already exist."
}
elseif ($SelfSigned) {
    & powershell.exe -NoProfile -ExecutionPolicy Bypass -File $setupScript -ProjectRoot $ProjectRoot -PublicIP $PublicIP -LanIP $LanIP -SelfSigned -ForceRecreate
    if ($LASTEXITCODE -ne 0) { throw "setup-public-https.ps1 failed." }
    Ok "Self-signed certificate installed for diagnostic use."
}
elseif (-not [string]::IsNullOrWhiteSpace($Email)) {
    & powershell.exe -NoProfile -ExecutionPolicy Bypass -File $setupScript -ProjectRoot $ProjectRoot -PublicIP $PublicIP -LanIP $LanIP -Email $Email -ForceRecreate
    if ($LASTEXITCODE -ne 0) { throw "setup-public-https.ps1 failed." }
    Ok "Certificate setup completed."
}
else {
    Warn "No certificate action requested. The existing certificate volume will be used."
}

Step "Start gateway with base plus public HTTPS Compose overlay"
$composeArguments = @(
    "compose",
    "--project-directory", $ProjectRoot,
    "--project-name", "aetheris-gateway",
    "-f", $baseCompose,
    "-f", $publicCompose,
    "up", "-d", "--force-recreate", "gateway"
)
$upResult = Invoke-NativeCapture -FilePath "docker.exe" -ArgumentList $composeArguments
Show-Lines $upResult
if ($upResult.ExitCode -ne 0) {
    throw "Could not start the gateway with the public HTTPS overlay. If port 443 is already allocated, rerun the diagnostic and identify the exact owner first."
}
Start-Sleep -Seconds 5

$gatewayIds = Invoke-NativeCapture -FilePath "docker.exe" -ArgumentList @(
    "ps",
    "--filter", "label=com.docker.compose.project=aetheris-gateway",
    "--filter", "label=com.docker.compose.service=gateway",
    "-q"
)
if ($gatewayIds.Lines.Count -eq 0) { throw "Gateway did not start." }
$gateway = ([string]$gatewayIds.Lines[0]).Trim()

$gatewayPs = Invoke-NativeCapture -FilePath "docker.exe" -ArgumentList @(
    "ps", "--filter", ("id={0}" -f $gateway), "--format", "{{.ID}}|{{.Names}}|{{.Status}}|{{.Ports}}"
)
Show-Lines $gatewayPs
if (($gatewayPs.Lines -join " ") -notmatch ':443->443/tcp') {
    throw "Gateway started but host 443 is still not published. Verify the public HTTPS Compose overlay."
}
Ok "Gateway now publishes host TCP 443."

Step "Validate Nginx syntax"
$nginxTest = Invoke-NativeCapture -FilePath "docker.exe" -ArgumentList @("exec", $gateway, "nginx", "-t")
Show-Lines $nginxTest
if ($nginxTest.ExitCode -ne 0) { throw "nginx -t failed." }
Ok "nginx -t passed."

Step "Verify TLS configuration"
$nginxDump = Invoke-NativeCapture -FilePath "docker.exe" -ArgumentList @("exec", $gateway, "nginx", "-T")
$tlsLines = @($nginxDump.Lines | Where-Object {
    $_ -match '^\s*listen\s+.*443' -or
    $_ -match '^\s*server_name\s+' -or
    $_ -match '^\s*ssl_certificate\s+' -or
    $_ -match '^\s*ssl_certificate_key\s+' -or
    $_ -match '^\s*ssl_protocols\s+'
})
$tlsLines | ForEach-Object { Write-Host $_ }
if (($nginxDump.Lines -join "`n") -notmatch 'listen\s+.*443.*ssl') {
    throw "Nginx still has no TLS 443 server block."
}

Step "Verify certificate path"
$certDirectory = "/etc/letsencrypt/live/$PublicIP"
$certList = Invoke-NativeCapture -FilePath "docker.exe" -ArgumentList @("exec", $gateway, "ls", "-la", $certDirectory)
Show-Lines $certList
if ($certList.ExitCode -ne 0) {
    throw "No certificate is mounted for $PublicIP. Re-run with -Email <address>, or use -SelfSigned only for diagnostic testing."
}

Step "Verify local TLS handshake"
$localProbe = Invoke-NativeCapture -FilePath "docker.exe" -ArgumentList @(
    "exec", $gateway, "wget", "-S", "-T", "10", "-O", "/dev/null", "--no-check-certificate", "https://127.0.0.1/api/health"
)
Show-Lines $localProbe
if ($localProbe.ExitCode -ne 0) {
    throw "Local TLS handshake still fails. Review the gateway logs and active Nginx TLS configuration."
}
Ok "Local TLS handshake succeeds."

Write-Host "`n=============================================================================="
Ok "Central gateway repair completed."
Write-Host "Now rerun Test-Aetheris-Central-TLS-v1.4.3.ps1 on this server, then Test-Docker-TLS-v1.4.0.ps1 on the client laptop."
