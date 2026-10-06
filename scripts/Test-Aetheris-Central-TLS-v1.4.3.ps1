[CmdletBinding()]
param(
    [string]$ProjectRoot = "",
    [string]$PublicIP = "122.179.140.167"
)

$ErrorActionPreference = "Stop"
$ProgressPreference = "SilentlyContinue"

function Step([string]$Message) { Write-Host "`n==== $Message ====" -ForegroundColor Cyan }
function Ok([string]$Message) { Write-Host "[OK] $Message" -ForegroundColor Green }
function Warn([string]$Message) { Write-Host "[WARN] $Message" -ForegroundColor Yellow }
function Fail([string]$Message) { Write-Host "[FAIL] $Message" -ForegroundColor Red }

function Invoke-NativeCapture {
    param(
        [Parameter(Mandatory = $true)][string]$FilePath,
        [string[]]$ArgumentList = @()
    )

    $oldPreference = $ErrorActionPreference
    $raw = @()
    $exitCode = 9009
    try {
        # Windows PowerShell 5.1 turns native STDERR into ErrorRecord objects.
        # Use Continue only for this native invocation, then stringify both streams.
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

    $lines = @($raw | ForEach-Object { [string]$_ })
    return [pscustomobject]@{
        ExitCode = $exitCode
        Lines = $lines
    }
}

function Show-Lines($Result) {
    if ($null -ne $Result -and $null -ne $Result.Lines) {
        $Result.Lines | ForEach-Object { Write-Host $_ }
    }
}

function Get-ProcessInfoForPid([int]$PidValue) {
    $processInfo = Get-CimInstance Win32_Process -Filter ("ProcessId={0}" -f $PidValue) -ErrorAction SilentlyContinue
    if ($null -eq $processInfo) {
        return [pscustomobject]@{
            PID = $PidValue
            Process = "<unknown>"
            Executable = ""
            CommandLine = ""
        }
    }
    return [pscustomobject]@{
        PID = $PidValue
        Process = [string]$processInfo.Name
        Executable = [string]$processInfo.ExecutablePath
        CommandLine = [string]$processInfo.CommandLine
    }
}

if ([string]::IsNullOrWhiteSpace($ProjectRoot)) {
    $ProjectRoot = (Resolve-Path (Join-Path $PSScriptRoot "..\..")).Path
}

$baseCompose = Join-Path $ProjectRoot "services\gateway\docker-compose.yml"
$httpsCompose = Join-Path $ProjectRoot "deployment\windows-ip-https\docker-compose.gateway-public-https.yml"

if (-not (Test-Path -LiteralPath $baseCompose)) {
    throw "ProjectRoot does not look like the Polaron/Aetheris repository: $ProjectRoot"
}

Set-Location $ProjectRoot

Write-Host "=============================================================================="
Write-Host "Aetheris Central TLS diagnostic v1.4.3"
Write-Host "=============================================================================="
Write-Host "ProjectRoot=$ProjectRoot"
Write-Host "PublicIP=$PublicIP"

$overallFailure = $false
$gateway = ""
$gatewayPublishes443 = $false
$containerListens443 = $false
$nginxTestPassed = $false

Step "Host TCP 443 listeners and owners"
$listeners443 = @(Get-NetTCPConnection -State Listen -LocalPort 443 -ErrorAction SilentlyContinue)
if ($listeners443.Count -eq 0) {
    Fail "Nothing is listening on Windows TCP 443."
    $overallFailure = $true
}
else {
    Ok ("TCP 443 is listening on the Windows host ({0} listener(s))." -f $listeners443.Count)
    $listenerRows = foreach ($listener in $listeners443) {
        $process = Get-ProcessInfoForPid -PidValue ([int]$listener.OwningProcess)
        [pscustomobject]@{
            LocalAddress = $listener.LocalAddress
            LocalPort = $listener.LocalPort
            PID = $process.PID
            Process = $process.Process
            Executable = $process.Executable
            CommandLine = $process.CommandLine
        }
    }
    $listenerRows | Format-Table -AutoSize -Wrap
}

Step "Docker containers and published ports"
$dockerPs = Invoke-NativeCapture -FilePath "docker.exe" -ArgumentList @("ps", "--format", "{{.ID}}|{{.Names}}|{{.Status}}|{{.Ports}}")
if ($dockerPs.ExitCode -ne 0) {
    Fail "docker ps failed. Docker Desktop/Linux engine may not be running."
    Show-Lines $dockerPs
    exit 2
}
Show-Lines $dockerPs

$docker443 = @($dockerPs.Lines | Where-Object { $_ -match ':443->' })
if ($docker443.Count -gt 0) {
    Write-Host "`nContainers publishing host 443:"
    $docker443 | ForEach-Object { Write-Host $_ }
}
else {
    Warn "No Docker container currently publishes host TCP 443."
}

Step "Aetheris gateway container"
$gatewayIds = Invoke-NativeCapture -FilePath "docker.exe" -ArgumentList @(
    "ps",
    "--filter", "label=com.docker.compose.project=aetheris-gateway",
    "--filter", "label=com.docker.compose.service=gateway",
    "-q"
)
if ($gatewayIds.ExitCode -ne 0 -or $gatewayIds.Lines.Count -eq 0) {
    Fail "No running aetheris-gateway/gateway container was found."
    $overallFailure = $true
}
else {
    $gateway = ([string]$gatewayIds.Lines[0]).Trim()
    Ok "Gateway container is running: $gateway"

    $gatewayPs = Invoke-NativeCapture -FilePath "docker.exe" -ArgumentList @(
        "ps", "--filter", ("id={0}" -f $gateway), "--format", "{{.ID}}|{{.Names}}|{{.Status}}|{{.Ports}}"
    )
    Show-Lines $gatewayPs
    $gatewayPortText = $gatewayPs.Lines -join " "
    $gatewayPublishes443 = $gatewayPortText -match ':443->443/tcp'
    if ($gatewayPublishes443) {
        Ok "The running Aetheris gateway publishes host TCP 443."
    }
    else {
        Fail "The running Aetheris gateway does NOT publish host TCP 443."
        Warn "The current container appears to be using only the base gateway compose definition."
        $overallFailure = $true
    }
}

if (-not [string]::IsNullOrWhiteSpace($gateway)) {
    Step "Gateway bind mounts"
    $inspectResult = Invoke-NativeCapture -FilePath "docker.exe" -ArgumentList @("inspect", $gateway)
    if ($inspectResult.ExitCode -ne 0) {
        Fail "docker inspect failed for gateway $gateway."
        Show-Lines $inspectResult
        $overallFailure = $true
    }
    else {
        try {
            $inspectJson = $inspectResult.Lines -join "`n"
            $inspectObjects = @($inspectJson | ConvertFrom-Json)
            $mounts = @($inspectObjects[0].Mounts)
            if ($mounts.Count -eq 0) {
                Warn "Gateway has no bind/volume mounts reported by docker inspect."
            }
            foreach ($mount in $mounts) {
                Write-Host (("{0} -> {1}" -f $mount.Source, $mount.Destination))
            }
            $activeDefaultConf = @($mounts | Where-Object { [string]$_.Destination -eq "/etc/nginx/conf.d/default.conf" })
            if ($activeDefaultConf.Count -gt 0) {
                $sourcePath = [string]$activeDefaultConf[0].Source
                Write-Host ("Active /etc/nginx/conf.d/default.conf source: {0}" -f $sourcePath)
                if ($sourcePath -match 'nginx\.gateway\.https\.conf') {
                    Ok "Public HTTPS Nginx config is mounted into the running gateway."
                }
                elseif ($sourcePath -match 'nginx-gateway\.conf') {
                    Fail "The running gateway is using the HTTP-only nginx-gateway.conf."
                    $overallFailure = $true
                }
                else {
                    Warn "The active default.conf comes from an unexpected source path."
                }
            }
            else {
                Warn "Could not find a mount whose destination is /etc/nginx/conf.d/default.conf."
            }
        }
        catch {
            Fail ("Could not parse docker inspect JSON: {0}" -f $_.Exception.Message)
            $overallFailure = $true
        }
    }

    Step "Nginx configuration syntax"
    $nginxTest = Invoke-NativeCapture -FilePath "docker.exe" -ArgumentList @("exec", $gateway, "nginx", "-t")
    Show-Lines $nginxTest
    if ($nginxTest.ExitCode -eq 0) {
        Ok "nginx -t passed."
        $nginxTestPassed = $true
    }
    else {
        Fail "nginx -t failed."
        $overallFailure = $true
    }

    Step "Active Nginx TLS configuration"
    $nginxDump = Invoke-NativeCapture -FilePath "docker.exe" -ArgumentList @("exec", $gateway, "nginx", "-T")
    $interestingNginxLines = @($nginxDump.Lines | Where-Object {
        $_ -match '^\s*listen\s+.*443' -or
        $_ -match '^\s*server_name\s+' -or
        $_ -match '^\s*ssl_certificate\s+' -or
        $_ -match '^\s*ssl_certificate_key\s+' -or
        $_ -match '^\s*ssl_protocols\s+'
    })
    if ($interestingNginxLines.Count -gt 0) {
        $interestingNginxLines | ForEach-Object { Write-Host $_ }
    }
    else {
        Warn "No TLS/listen/server_name lines were found in nginx -T output."
    }
    $nginxText = $nginxDump.Lines -join "`n"
    $containerListens443 = $nginxText -match 'listen\s+.*443.*ssl'
    if ($containerListens443) {
        Ok "Nginx inside the gateway has a TLS server block on 443."
    }
    else {
        Fail "Nginx inside the gateway has no TLS 443 server block."
        $overallFailure = $true
    }
}

Step "Effective Compose configuration for public HTTPS"
if (-not (Test-Path -LiteralPath $httpsCompose)) {
    Fail "Missing HTTPS compose overlay: $httpsCompose"
    $overallFailure = $true
}
else {
    $composeConfig = Invoke-NativeCapture -FilePath "docker.exe" -ArgumentList @(
        "compose",
        "--project-directory", $ProjectRoot,
        "--project-name", "aetheris-gateway",
        "-f", $baseCompose,
        "-f", $httpsCompose,
        "config"
    )
    if ($composeConfig.ExitCode -ne 0) {
        Fail "Could not render the combined public HTTPS compose configuration."
        Show-Lines $composeConfig
        $overallFailure = $true
    }
    else {
        $composeText = $composeConfig.Lines -join "`n"
        $composePortLines = @($composeConfig.Lines | Where-Object {
            $_ -match 'published:\s*["'']?443["'']?' -or
            $_ -match 'target:\s*443'
        })
        $composePortLines | ForEach-Object { Write-Host $_ }
        if ($composeText -match 'published:\s*["'']?443["'']?') {
            Ok "The combined public HTTPS Compose configuration publishes host 443."
        }
        else {
            Fail "The combined public HTTPS Compose configuration does not publish host 443."
            $overallFailure = $true
        }
    }
}

if (-not [string]::IsNullOrWhiteSpace($gateway)) {
    Step "Certificate path inside gateway"
    if ($containerListens443) {
        $certDirectory = "/etc/letsencrypt/live/$PublicIP"
        $certList = Invoke-NativeCapture -FilePath "docker.exe" -ArgumentList @("exec", $gateway, "ls", "-la", $certDirectory)
        Show-Lines $certList
        if ($certList.ExitCode -eq 0) {
            Ok "Certificate directory for $PublicIP exists inside the gateway."
        }
        else {
            Fail "Certificate directory is missing inside the gateway: $certDirectory"
            $overallFailure = $true
        }
    }
    else {
        Warn "Skipping certificate test because Nginx is not configured for TLS 443."
    }

    Step "Local TLS handshake inside gateway"
    if ($containerListens443) {
        $localProbe = Invoke-NativeCapture -FilePath "docker.exe" -ArgumentList @(
            "exec", $gateway, "wget", "-S", "-T", "8", "-O", "/dev/null", "--no-check-certificate", "https://127.0.0.1/api/health"
        )
        Show-Lines $localProbe
        if ($localProbe.ExitCode -eq 0) {
            Ok "Local TLS handshake completed inside the gateway."
        }
        else {
            Fail "Local TLS handshake failed inside the gateway."
            $overallFailure = $true
        }
    }
    else {
        Warn "Skipping local TLS handshake because Nginx is not listening on TLS 443."
    }

    Step "Recent gateway logs"
    $gatewayLogs = Invoke-NativeCapture -FilePath "docker.exe" -ArgumentList @("logs", "--tail", "120", $gateway)
    Show-Lines $gatewayLogs
}

Step "Assessment"
if (-not $gatewayPublishes443) {
    Write-Host "The running Aetheris gateway is not bound to host 443."
    Write-Host "Do not stop an unknown 443 owner blindly. Use the PID/process and Docker port list above first."
    Write-Host "After host 443 is available, start the gateway with BOTH compose files:"
    Write-Host ""
    $startCommand = 'docker compose --project-directory "{0}" --project-name aetheris-gateway -f "{1}" -f "{2}" up -d --force-recreate gateway' -f $ProjectRoot, $baseCompose, $httpsCompose
    Write-Host $startCommand
}

Write-Host "`n=============================================================================="
if (-not $overallFailure -and $gatewayPublishes443 -and $containerListens443 -and $nginxTestPassed) {
    Ok "Central TLS gateway diagnostic passed the structural checks."
    exit 0
}
Fail "Central TLS gateway still has one or more blocking issues shown above."
exit 3
