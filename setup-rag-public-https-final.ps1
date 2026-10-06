[CmdletBinding()]
param(
    [string]$ProjectRoot = "F:\rag_new2",
    [string]$WiFiAlias = "Wi-Fi 3",
    [string]$ServerIP = "192.168.1.56",
    [int]$PrefixLength = 24,
    [string]$Gateway = "192.168.1.1",
    [string]$PublicIP = "122.170.114.36",
    [string]$OtherGateway = "192.168.4.1",
    [int]$AirtelRouteMetric = 5,
    [int]$OtherRouteMetric = 500,
    [string[]]$DnsServers = @("1.1.1.1", "8.8.8.8"),
    [string]$Email = "",
    [string]$ComposeFile = "",
    [switch]$IssueCertificate,
    [switch]$SkipStaticIP,
    [switch]$SkipDocker
)

$ErrorActionPreference = "Stop"
$ProgressPreference = "SilentlyContinue"

# Keep all existing/orphan containers untouched. Docker Compose supports
# COMPOSE_IGNORE_ORPHANS=true to skip orphan detection/warnings and
# COMPOSE_REMOVE_ORPHANS=false to ensure Compose never auto-removes them.
$env:COMPOSE_IGNORE_ORPHANS = "true"
$env:COMPOSE_REMOVE_ORPHANS = "false"
$env:COMPOSE_PROGRESS = "plain"

function Write-Step {
    param([string]$Message)
    Write-Host "`n============================================================" -ForegroundColor Cyan
    Write-Host $Message -ForegroundColor Cyan
    Write-Host "============================================================" -ForegroundColor Cyan
}

function Write-Ok {
    param([string]$Message)
    Write-Host "[OK] $Message" -ForegroundColor Green
}

function Write-WarnMsg {
    param([string]$Message)
    Write-Warning $Message
}

function Assert-Administrator {
    $identity = [Security.Principal.WindowsIdentity]::GetCurrent()
    $principal = New-Object Security.Principal.WindowsPrincipal($identity)
    $isAdmin = $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
    if (-not $isAdmin) {
        throw "Run PowerShell as Administrator, then run this script again."
    }
}

function Ensure-FirewallRule {
    param(
        [string]$Name,
        [int]$Port
    )

    $existing = Get-NetFirewallRule -DisplayName $Name -ErrorAction SilentlyContinue
    if ($existing) {
        $existing | Set-NetFirewallRule -Enabled True -Direction Inbound -Action Allow -Profile Any | Out-Null
        Write-Ok "Firewall rule enabled: $Name"
        return
    }

    New-NetFirewallRule `
        -DisplayName $Name `
        -Direction Inbound `
        -Action Allow `
        -Protocol TCP `
        -LocalPort $Port `
        -Profile Any | Out-Null

    Write-Ok "Firewall rule created: $Name"
}

function Invoke-DockerProcess {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$true)]
        [string]$Arguments,
        [switch]$CaptureOutput,
        [switch]$SuppressStderr
    )

    # IMPORTANT: Start-Process is used intentionally instead of & docker.
    # Docker/Compose writes normal progress and warnings to stderr. In Windows
    # PowerShell 5.x, $ErrorActionPreference='Stop' can convert those harmless
    # stderr lines into NativeCommandError and terminate the script. Start-Process
    # keeps native stderr out of PowerShell's error stream. Docker's numeric exit
    # code is the only success/failure signal used here.
    $dockerCommand = Get-Command docker.exe -ErrorAction SilentlyContinue
    if (-not $dockerCommand) {
        $dockerCommand = Get-Command docker -ErrorAction SilentlyContinue
    }
    if (-not $dockerCommand) {
        throw "Docker CLI was not found. Install/start Docker Desktop and rerun the script."
    }

    $dockerExe = $dockerCommand.Source

    if ($CaptureOutput) {
        $stdoutFile = [System.IO.Path]::GetTempFileName()
        $stderrFile = [System.IO.Path]::GetTempFileName()
        try {
            $process = Start-Process `
                -FilePath $dockerExe `
                -ArgumentList $Arguments `
                -NoNewWindow `
                -Wait `
                -PassThru `
                -RedirectStandardOutput $stdoutFile `
                -RedirectStandardError $stderrFile

            $stdout = if (Test-Path $stdoutFile) { [System.IO.File]::ReadAllText($stdoutFile) } else { "" }
            $stderr = if (Test-Path $stderrFile) { [System.IO.File]::ReadAllText($stderrFile) } else { "" }

            if ((-not $SuppressStderr) -and (-not [string]::IsNullOrWhiteSpace($stderr))) {
                Write-Host $stderr.TrimEnd() -ForegroundColor DarkGray
            }

            return [pscustomobject]@{
                ExitCode = [int]$process.ExitCode
                StdOut   = $stdout
                StdErr   = $stderr
            }
        }
        finally {
            Remove-Item $stdoutFile,$stderrFile -Force -ErrorAction SilentlyContinue
        }
    }

    $process = Start-Process `
        -FilePath $dockerExe `
        -ArgumentList $Arguments `
        -NoNewWindow `
        -Wait `
        -PassThru

    return [pscustomobject]@{
        ExitCode = [int]$process.ExitCode
        StdOut   = ""
        StdErr   = ""
    }
}

function Invoke-DockerChecked {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$true)]
        [string]$Arguments,
        [Parameter(Mandatory=$true)]
        [string]$FailureMessage,
        [switch]$CaptureOutput,
        [switch]$SuppressStderr
    )

    $result = Invoke-DockerProcess `
        -Arguments $Arguments `
        -CaptureOutput:$CaptureOutput `
        -SuppressStderr:$SuppressStderr

    if ($result.ExitCode -ne 0) {
        if ($CaptureOutput -and -not [string]::IsNullOrWhiteSpace($result.StdOut)) {
            Write-Host $result.StdOut.TrimEnd()
        }
        if ($CaptureOutput -and -not [string]::IsNullOrWhiteSpace($result.StdErr)) {
            Write-Host $result.StdErr.TrimEnd() -ForegroundColor Yellow
        }
        throw "$FailureMessage (Docker exit code $($result.ExitCode))."
    }

    return $result
}

function Resolve-ComposeFile {
    param(
        [string]$Root,
        [string]$RequestedFile,
        [bool]$NeedCertificateServices
    )

    $candidates = @()

    if (-not [string]::IsNullOrWhiteSpace($RequestedFile)) {
        $requestedPath = $RequestedFile
        if (-not [System.IO.Path]::IsPathRooted($requestedPath)) {
            $requestedPath = Join-Path $Root $requestedPath
        }
        $candidates += $requestedPath
    }
    else {
        # Prefer the HTTPS-ready compose file generated for this project.
        $candidates += @(
            (Join-Path $Root "docker-compose(7).yml"),
            (Join-Path $Root "docker-compose.yml"),
            (Join-Path $Root "docker-compose.yaml"),
            (Join-Path $Root "compose.yml"),
            (Join-Path $Root "compose.yaml")
        )
    }

    $existing = @($candidates | Where-Object { Test-Path $_ })
    if ($existing.Count -eq 0) {
        return $null
    }

    foreach ($candidate in $existing) {
        Write-Host "Checking Compose file: $candidate" -ForegroundColor DarkCyan
        $candidateCheck = Invoke-DockerProcess -Arguments "compose -f `"$candidate`" --profile certbot --profile acme-bootstrap config --services" -CaptureOutput -SuppressStderr
        if ($candidateCheck.ExitCode -ne 0) {
            Write-WarnMsg "Skipping invalid Compose file: $candidate"
            continue
        }
        $candidateServices = @($candidateCheck.StdOut -split "`r?`n" | Where-Object { -not [string]::IsNullOrWhiteSpace($_) } | ForEach-Object { $_.Trim() })

        $hasCore = ($candidateServices -contains "frontend") -and ($candidateServices -contains "api")
        $hasCert = ($candidateServices -contains "certbot") -and ($candidateServices -contains "acme-bootstrap")

        if ($hasCore -and ((-not $NeedCertificateServices) -or $hasCert)) {
            return (Resolve-Path $candidate).Path
        }

        if ($NeedCertificateServices -and $hasCore -and (-not $hasCert)) {
            Write-WarnMsg "Compose file does not contain certbot/acme-bootstrap: $candidate"
        }
    }

    return $null
}

function Test-ExternalPublicIP {
    param([string]$ExpectedIP)

    try {
        $actual = (Invoke-RestMethod -Uri "https://api4.ipify.org" -TimeoutSec 15).ToString().Trim()
        Write-Host "Detected public IP : $actual"
        Write-Host "Expected public IP : $ExpectedIP"

        if ($actual -eq $ExpectedIP) {
            Write-Ok "Public IP matches Airtel static IP $ExpectedIP"
            return $true
        }

        Write-WarnMsg "Public IP does not match $ExpectedIP. Do not request the certificate until the Airtel connection is the active Internet path."
        return $false
    }
    catch {
        Write-WarnMsg "Could not verify public IP using api4.ipify.org: $($_.Exception.Message)"
        return $false
    }
}

Assert-Administrator

Write-Host "Docker orphan policy: IGNORE orphan warnings; DO NOT remove orphan containers." -ForegroundColor Yellow
Write-Host "COMPOSE_IGNORE_ORPHANS=$env:COMPOSE_IGNORE_ORPHANS; COMPOSE_REMOVE_ORPHANS=$env:COMPOSE_REMOVE_ORPHANS" -ForegroundColor DarkGray
Write-Host "Docker stderr/progress is isolated from PowerShell ErrorActionPreference; only Docker exit codes can fail Docker steps." -ForegroundColor DarkGray

Write-Step "1. Save current Windows network configuration"

if (-not (Test-Path $ProjectRoot)) {
    New-Item -ItemType Directory -Path $ProjectRoot -Force | Out-Null
}

$deploymentDir = Join-Path $ProjectRoot "deployment\windows-ip-https"
New-Item -ItemType Directory -Path $deploymentDir -Force | Out-Null

$timestamp = Get-Date -Format "yyyyMMdd-HHmmss"
$backupFile = Join-Path $deploymentDir "network-before-$timestamp.txt"

"=== Get-NetAdapter ===" | Out-File $backupFile -Encoding utf8
Get-NetAdapter -IncludeHidden | Format-List * | Out-File $backupFile -Append -Encoding utf8
"`n=== Get-NetIPConfiguration ===" | Out-File $backupFile -Append -Encoding utf8
Get-NetIPConfiguration | Format-List * | Out-File $backupFile -Append -Encoding utf8
"`n=== Get-NetRoute IPv4 ===" | Out-File $backupFile -Append -Encoding utf8
Get-NetRoute -AddressFamily IPv4 | Sort-Object DestinationPrefix,RouteMetric | Format-Table -AutoSize | Out-File $backupFile -Append -Encoding utf8
"`n=== route print -4 ===" | Out-File $backupFile -Append -Encoding utf8
route.exe print -4 | Out-File $backupFile -Append -Encoding utf8

Write-Ok "Network backup written to $backupFile"

Write-Step "2. Resolve the live Airtel/Wi-Fi interface"

$adapter = Get-NetAdapter -Name $WiFiAlias -ErrorAction SilentlyContinue
if (-not $adapter) {
    Write-Host "Available adapters:" -ForegroundColor Yellow
    Get-NetAdapter -IncludeHidden | Format-Table ifIndex,Name,Status,MacAddress,InterfaceDescription
    throw "Adapter '$WiFiAlias' was not found. Set -WiFiAlias to the exact adapter name shown above."
}

if ($adapter.Status -eq "Disabled") {
    Enable-NetAdapter -Name $WiFiAlias -Confirm:$false
    Start-Sleep -Seconds 2
    $adapter = Get-NetAdapter -Name $WiFiAlias
}

if ($adapter.Status -ne "Up") {
    Write-WarnMsg "Adapter '$WiFiAlias' status is '$($adapter.Status)'. Connect it to the Airtel router before certificate issuance."
}

$ifIndex = [int]$adapter.ifIndex
Write-Host "Airtel interface : $WiFiAlias"
Write-Host "Current ifIndex  : $ifIndex"
Write-Host "MAC address      : $($adapter.MacAddress)"

$ipInterface = Get-NetIPInterface -InterfaceIndex $ifIndex -AddressFamily IPv4 -ErrorAction SilentlyContinue
if (-not $ipInterface) {
    throw "No IPv4 NetIPInterface object exists for '$WiFiAlias' (ifIndex $ifIndex)."
}

Set-NetIPInterface `
    -InterfaceIndex $ifIndex `
    -AddressFamily IPv4 `
    -AutomaticMetric Disabled `
    -InterfaceMetric 10

Write-Ok "Set $WiFiAlias IPv4 interface metric to 10"

Write-Step "3. Configure 192.168.1.56/24 on the Airtel interface"

if (-not $SkipStaticIP) {
    Set-NetIPInterface -InterfaceIndex $ifIndex -AddressFamily IPv4 -Dhcp Disabled

    $currentIPv4 = @(
        Get-NetIPAddress -InterfaceIndex $ifIndex -AddressFamily IPv4 -ErrorAction SilentlyContinue |
        Where-Object {
            $_.IPAddress -notlike "169.254.*" -and
            $_.IPAddress -ne "0.0.0.0"
        }
    )

    $targetAddress = $currentIPv4 | Where-Object {
        $_.IPAddress -eq $ServerIP -and $_.PrefixLength -eq $PrefixLength
    }

    if (-not $targetAddress) {
        # Remove default routes associated with this interface before replacing its address.
        Get-NetRoute `
            -InterfaceIndex $ifIndex `
            -AddressFamily IPv4 `
            -DestinationPrefix "0.0.0.0/0" `
            -ErrorAction SilentlyContinue |
        Remove-NetRoute -Confirm:$false -ErrorAction SilentlyContinue

        foreach ($address in $currentIPv4) {
            Write-Host "Removing old IPv4 address $($address.IPAddress)/$($address.PrefixLength) from $WiFiAlias"
            $address | Remove-NetIPAddress -Confirm:$false -ErrorAction SilentlyContinue
        }

        New-NetIPAddress `
            -InterfaceIndex $ifIndex `
            -IPAddress $ServerIP `
            -PrefixLength $PrefixLength | Out-Null

        Write-Ok "Configured $ServerIP/$PrefixLength on $WiFiAlias"
    }
    else {
        Write-Ok "$ServerIP/$PrefixLength is already configured on $WiFiAlias"
    }

    Set-DnsClientServerAddress -InterfaceIndex $ifIndex -ServerAddresses $DnsServers
    Write-Ok "DNS servers set to $($DnsServers -join ', ')"
}
else {
    Write-WarnMsg "Skipped changing the static IP because -SkipStaticIP was supplied."
}

Write-Step "4. Ensure the Airtel default route exists and is preferred"

$airtelRoutes = @(
    Get-NetRoute -AddressFamily IPv4 -DestinationPrefix "0.0.0.0/0" -ErrorAction SilentlyContinue |
    Where-Object {
        $_.InterfaceIndex -eq $ifIndex -and $_.NextHop -eq $Gateway
    }
)

if ($airtelRoutes.Count -eq 0) {
    try {
        New-NetRoute `
            -DestinationPrefix "0.0.0.0/0" `
            -InterfaceIndex $ifIndex `
            -NextHop $Gateway `
            -RouteMetric $AirtelRouteMetric `
            -PolicyStore PersistentStore | Out-Null

        Write-Ok "Created persistent Airtel default route via $Gateway"
    }
    catch {
        Write-WarnMsg "Persistent route creation returned: $($_.Exception.Message). Trying ActiveStore."
        New-NetRoute `
            -DestinationPrefix "0.0.0.0/0" `
            -InterfaceIndex $ifIndex `
            -NextHop $Gateway `
            -RouteMetric $AirtelRouteMetric `
            -PolicyStore ActiveStore | Out-Null
    }
}
else {
    foreach ($route in $airtelRoutes) {
        try {
            $route | Set-NetRoute -RouteMetric $AirtelRouteMetric
        }
        catch {
            Write-WarnMsg "Could not update one Airtel route instance: $($_.Exception.Message)"
        }
    }
    Write-Ok "Airtel default route metric set to $AirtelRouteMetric"
}

# Re-read in case a PersistentStore route needed time to become active.
Start-Sleep -Seconds 1
$activeAirtelRoute = Get-NetRoute -AddressFamily IPv4 -DestinationPrefix "0.0.0.0/0" -ErrorAction SilentlyContinue |
    Where-Object { $_.NextHop -eq $Gateway } |
    Sort-Object RouteMetric |
    Select-Object -First 1

if (-not $activeAirtelRoute) {
    throw "No active default route through Airtel gateway $Gateway exists after configuration."
}

Write-Step "5. De-prioritize the old 192.168.4.1 default route if it exists"

$otherRoutes = @(
    Get-NetRoute -AddressFamily IPv4 -DestinationPrefix "0.0.0.0/0" -ErrorAction SilentlyContinue |
    Where-Object { $_.NextHop -eq $OtherGateway }
)

if ($otherRoutes.Count -eq 0) {
    Write-Ok "No current default route through $OtherGateway exists. Nothing to change."
}
else {
    foreach ($route in $otherRoutes) {
        try {
            $route | Set-NetRoute -RouteMetric $OtherRouteMetric
            Write-Ok "Changed route via $OtherGateway on ifIndex $($route.InterfaceIndex) to metric $OtherRouteMetric"
        }
        catch {
            Write-WarnMsg "Could not change route via $OtherGateway on ifIndex $($route.InterfaceIndex): $($_.Exception.Message)"
        }
    }
}

Write-Step "6. Open Windows Firewall ports 80 and 443"

Ensure-FirewallRule -Name "RAG Public HTTP 80" -Port 80
Ensure-FirewallRule -Name "RAG Public HTTPS 443" -Port 443

Write-Step "7. Verify Windows network state"

Write-Host "`nIPv4 address on Airtel interface:"
Get-NetIPAddress -InterfaceIndex $ifIndex -AddressFamily IPv4 -ErrorAction SilentlyContinue |
    Format-Table InterfaceAlias,InterfaceIndex,IPAddress,PrefixLength,AddressState

Write-Host "`nDefault routes:"
Get-NetRoute -AddressFamily IPv4 -DestinationPrefix "0.0.0.0/0" -ErrorAction SilentlyContinue |
    Sort-Object RouteMetric |
    Format-Table ifIndex,InterfaceAlias,NextHop,RouteMetric,PolicyStore

Write-Host "`nAirtel gateway test:"
if (Test-Connection -ComputerName $Gateway -Count 2 -Quiet) {
    Write-Ok "Gateway $Gateway responds"
}
else {
    Write-WarnMsg "Gateway $Gateway did not respond to ICMP. Some routers block ping, so continue with the public-IP check."
}

$publicIPMatches = Test-ExternalPublicIP -ExpectedIP $PublicIP

Write-Step "8. Verify local listeners before Docker deployment"

Get-NetTCPConnection -State Listen -ErrorAction SilentlyContinue |
    Where-Object { $_.LocalPort -in 80,443,8080,8443 } |
    Sort-Object LocalPort |
    Format-Table LocalAddress,LocalPort,OwningProcess

if ($SkipDocker) {
    Write-WarnMsg "Docker setup was skipped because -SkipDocker was supplied."
    Write-Host "Network setup is complete."
    exit 0
}

Write-Step "9. Validate Docker Desktop and Docker Compose"

if (-not (Get-Command docker -ErrorAction SilentlyContinue)) {
    throw "Docker CLI was not found. Install/start Docker Desktop and rerun the script."
}

$null = Invoke-DockerChecked -Arguments "version" -FailureMessage "Docker Desktop/daemon is not available. Start Docker Desktop and rerun the script"
$null = Invoke-DockerChecked -Arguments "compose version" -FailureMessage "Docker Compose v2 is not available"

$composeFile = Resolve-ComposeFile -Root $ProjectRoot -RequestedFile $ComposeFile -NeedCertificateServices ([bool]$IssueCertificate)
if (-not $composeFile) {
    if ($IssueCertificate) {
        throw "No Compose file under $ProjectRoot contains all required services: frontend, api, certbot, acme-bootstrap. If docker-compose(7).yml exists, run with -ComposeFile 'docker-compose(7).yml'."
    }
    throw "No valid Docker Compose file containing frontend and api was found under $ProjectRoot."
}

Write-Ok "Using Compose file: $composeFile"
Set-Location $ProjectRoot

$null = Invoke-DockerChecked -Arguments "compose -f `"$composeFile`" config --quiet" -FailureMessage "docker compose config validation failed for $composeFile"
$serviceResult = Invoke-DockerChecked -Arguments "compose -f `"$composeFile`" --profile certbot --profile acme-bootstrap config --services" -FailureMessage "Could not enumerate Docker Compose services" -CaptureOutput -SuppressStderr
$services = @($serviceResult.StdOut -split "`r?`n" | Where-Object { -not [string]::IsNullOrWhiteSpace($_) } | ForEach-Object { $_.Trim() })

Write-Host "Compose services: $($services -join ', ')"
Write-Ok "Compose file contains the services required for this run"

foreach ($requiredService in @("frontend", "api")) {
    if ($services -notcontains $requiredService) {
        throw "Required Compose service '$requiredService' is missing."
    }
}

Write-Step "10. Write the production Nginx HTTPS configuration"

$nginxPath = Join-Path $deploymentDir "nginx.https.conf"

$nginxTemplate = @'
resolver 127.0.0.11 valid=10s ipv6=off;

server {
    listen 80;
    listen [::]:80;
    server_name __PUBLIC_IP__;

    location ^~ /.well-known/acme-challenge/ {
        root /var/www/certbot;
        default_type text/plain;
        try_files $uri =404;
    }

    location / {
        return 301 https://$host$request_uri;
    }
}

server {
    listen 443 ssl;
    listen [::]:443 ssl;
    server_name __PUBLIC_IP__;

    ssl_certificate     /etc/letsencrypt/live/__PUBLIC_IP__/fullchain.pem;
    ssl_certificate_key /etc/letsencrypt/live/__PUBLIC_IP__/privkey.pem;
    ssl_protocols TLSv1.2 TLSv1.3;
    ssl_session_cache shared:SSL:10m;
    ssl_session_timeout 1d;

    root /usr/share/nginx/html;
    index index.html;
    server_tokens off;
    client_max_body_size 0;

    location ^~ /.well-known/acme-challenge/ {
        root /var/www/certbot;
        default_type text/plain;
        try_files $uri =404;
    }

    location /api/ {
        proxy_pass http://api:8080;
        proxy_http_version 1.1;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
        proxy_set_header X-Forwarded-Host $host;
        proxy_set_header X-Forwarded-Port $server_port;
        proxy_set_header Authorization $http_authorization;
        proxy_set_header Upgrade $http_upgrade;
        proxy_set_header Connection "upgrade";
        proxy_connect_timeout 30s;
        proxy_send_timeout 3600s;
        proxy_read_timeout 3600s;
        proxy_buffering off;
        proxy_cache off;
    }

    location /assets/ {
        expires 1y;
        add_header Cache-Control "public, immutable";
        try_files $uri =404;
    }

    location / {
        try_files $uri $uri/ /index.html;
    }
}
'@

$nginxTemplate.Replace("__PUBLIC_IP__", $PublicIP) |
    Set-Content -Path $nginxPath -Encoding UTF8

Write-Ok "Nginx configuration written to $nginxPath"

if (-not $IssueCertificate) {
    Write-Step "11. Network/Docker preparation complete"
    Write-Host "The certificate step was not requested."
    Write-Host "Ensure the Airtel router forwards:"
    Write-Host "  TCP 80  -> $ServerIP`:80"
    Write-Host "  TCP 443 -> $ServerIP`:443"
    Write-Host "Then rerun:"
    Write-Host ".\setup-rag-public-https-v4.ps1 -ComposeFile ".\docker-compose.https.yml" -Email your-real-email@example.com -IssueCertificate" -ForegroundColor Yellow
    exit 0
}

if ([string]::IsNullOrWhiteSpace($Email) -or $Email -match "example\.com") {
    throw "Supply a real email address using -Email before requesting a Let's Encrypt certificate."
}

foreach ($requiredService in @("certbot", "acme-bootstrap")) {
    if ($services -notcontains $requiredService) {
        throw "Compose service '$requiredService' is required for automated IP-certificate issuance but is missing."
    }
}

if (-not $publicIPMatches) {
    throw "Certificate issuance stopped because the detected Internet public IP did not match $PublicIP."
}

Write-Step "11. Start the temporary ACME HTTP server on port 80"

$frontendStop = Invoke-DockerProcess -Arguments "compose -f `"$composeFile`" stop frontend"
if ($frontendStop.ExitCode -ne 0) {
    Write-WarnMsg "Frontend was not stopped cleanly. Continuing; ACME bootstrap will prove whether port 80 is free."
}

$null = Invoke-DockerChecked -Arguments "compose -f `"$composeFile`" --profile acme-bootstrap up -d acme-bootstrap" -FailureMessage "Failed to start the acme-bootstrap service. Check whether port 80 is already in use"

Start-Sleep -Seconds 2

Write-Step "12. Test the ACME webroot locally"

$acmeCommand = "mkdir -p /var/www/certbot/.well-known/acme-challenge && echo RAG-ACME-TEST > /var/www/certbot/.well-known/acme-challenge/test.txt"
$null = Invoke-DockerChecked -Arguments "compose -f `"$composeFile`" --profile certbot run --entrypoint sh certbot -c `"$acmeCommand`"" -FailureMessage "Could not create the ACME test file"

$localChallengeUrl = "http://127.0.0.1/.well-known/acme-challenge/test.txt"
try {
    $challengeResponse = (Invoke-WebRequest -Uri $localChallengeUrl -UseBasicParsing -TimeoutSec 10).Content.Trim()
    if ($challengeResponse -ne "RAG-ACME-TEST") {
        throw "Unexpected ACME response: $challengeResponse"
    }
    Write-Ok "Local ACME challenge path works on port 80"
}
catch {
    throw "Local ACME HTTP test failed. Check port 80 and acme-bootstrap. $($_.Exception.Message)"
}

Write-Host "`nIMPORTANT: the Airtel router must already forward TCP 80 to $ServerIP`:80."
Write-Host "Certbot staging validation will now prove whether the path is reachable from the public Internet."

Write-Step "13. Verify Certbot version"

# No --rm or --remove-orphans option is used anywhere in this script.
# Existing/orphan containers and one-shot Certbot helper containers are not deleted.

$null = Invoke-DockerChecked -Arguments "compose -f `"$composeFile`" --profile certbot run certbot --version" -FailureMessage "Certbot could not run"

Write-Step "14. Request a Let's Encrypt STAGING IP certificate"

$existingCertsResult = Invoke-DockerProcess -Arguments "compose -f `"$composeFile`" --profile certbot run certbot certificates" -CaptureOutput -SuppressStderr
$existingCertText = if ($existingCertsResult.ExitCode -eq 0) { $existingCertsResult.StdOut } else { "" }
$stagingName = "$PublicIP-staging"
$stagingExists = $existingCertText -match ("(?m)^\s*Certificate Name:\s*" + [regex]::Escape($stagingName) + "\s*$")

if ($stagingExists) {
    Write-Ok "Staging certificate $stagingName already exists; skipping duplicate staging issuance."
}
else {
    $stagingArgs = "compose -f `"$composeFile`" --profile certbot run certbot certonly --staging --preferred-profile shortlived --webroot --webroot-path /var/www/certbot --ip-address $PublicIP --cert-name `"$stagingName`" --email `"$Email`" --agree-tos --non-interactive"
    $null = Invoke-DockerChecked -Arguments $stagingArgs -FailureMessage "Let's Encrypt STAGING validation failed. Check Airtel TCP 80 -> $ServerIP`:80, Windows Firewall, WAN public IP, and double-NAT/CGNAT conditions"
    Write-Ok "Staging certificate validation succeeded"
}

Write-Step "15. Request the trusted production IP certificate"

$certificateResult = Invoke-DockerProcess -Arguments "compose -f `"$composeFile`" --profile certbot run certbot certificates" -CaptureOutput -SuppressStderr
if ($certificateResult.ExitCode -ne 0) {
    Write-WarnMsg "Could not list existing Certbot certificates cleanly. Continuing to production issuance based on Docker exit codes only."
    $certificateListing = ""
}
else {
    $certificateListing = $certificateResult.StdOut
}

$alreadyExists = $certificateListing -match ("(?m)^\s*Certificate Name:\s*" + [regex]::Escape($PublicIP) + "\s*$")

if ($alreadyExists) {
    Write-Ok "A production certificate named $PublicIP already exists; skipping duplicate issuance."
}
else {
    $productionArgs = "compose -f `"$composeFile`" --profile certbot run certbot certonly --preferred-profile shortlived --webroot --webroot-path /var/www/certbot --ip-address $PublicIP --cert-name `"$PublicIP`" --email `"$Email`" --agree-tos --non-interactive"
    $null = Invoke-DockerChecked -Arguments $productionArgs -FailureMessage "Production certificate issuance failed. ACME bootstrap has been left running for troubleshooting"
}

# Verify the production certificate after issuance/skip.
$verifyCertResult = Invoke-DockerChecked -Arguments "compose -f `"$composeFile`" --profile certbot run certbot certificates" -FailureMessage "Could not verify the production certificate" -CaptureOutput -SuppressStderr
if ($verifyCertResult.StdOut -notmatch ("(?m)^\s*Certificate Name:\s*" + [regex]::Escape($PublicIP) + "\s*$")) {
    throw "Certbot completed but certificate '$PublicIP' was not found in the certificate listing."
}

Write-Ok "Trusted IP certificate is available for $PublicIP"

Write-Step "16. Stop (do not remove) ACME bootstrap and start the real Docker application"

$bootstrapStop = Invoke-DockerProcess -Arguments "compose -f `"$composeFile`" --profile acme-bootstrap stop acme-bootstrap"
if ($bootstrapStop.ExitCode -ne 0) {
    Write-WarnMsg "Could not stop acme-bootstrap cleanly. No containers were removed. Check port 80 if frontend cannot start."
}

$null = Invoke-DockerChecked -Arguments "compose -f `"$composeFile`" up -d --build" -FailureMessage "docker compose up failed. Inspect with: docker compose -f `"$composeFile`" logs --tail=200"

Write-Step "17. Validate Nginx and application status"

$null = Invoke-DockerChecked -Arguments "compose -f `"$composeFile`" exec -T frontend nginx -t" -FailureMessage "Nginx configuration test failed"
$null = Invoke-DockerProcess -Arguments "compose -f `"$composeFile`" ps"

try {
    $health = Invoke-WebRequest -Uri "http://127.0.0.1:8080/health" -UseBasicParsing -TimeoutSec 15
    Write-Ok "API local health endpoint returned HTTP $($health.StatusCode)"
}
catch {
    Write-WarnMsg "API did not answer http://127.0.0.1:8080/health yet. Check: docker compose -f `"$composeFile`" logs --tail=200 api"
}

Write-Step "18. Create automatic certificate-renewal script"

$renewScript = Join-Path $deploymentDir "renew-ip-cert.ps1"
$escapedComposeFile = $composeFile.Replace("'", "''")
$escapedProjectRoot = $ProjectRoot.Replace("'", "''")

$renewContent = @"
`$ErrorActionPreference = 'Stop'
`$env:COMPOSE_IGNORE_ORPHANS = 'true'
`$env:COMPOSE_REMOVE_ORPHANS = 'false'
`$env:COMPOSE_PROGRESS = 'plain'
`$ComposeFile = '$escapedComposeFile'
Set-Location '$escapedProjectRoot'

function Invoke-DockerSafe {
    param([Parameter(Mandatory=`$true)][string]`$Arguments)
    `$dockerCommand = Get-Command docker.exe -ErrorAction SilentlyContinue
    if (-not `$dockerCommand) { `$dockerCommand = Get-Command docker -ErrorAction SilentlyContinue }
    if (-not `$dockerCommand) { throw 'Docker CLI was not found.' }
    `$p = Start-Process -FilePath `$dockerCommand.Source -ArgumentList `$Arguments -NoNewWindow -Wait -PassThru
    return [int]`$p.ExitCode
}

# No --rm and no --remove-orphans: this renewal job deletes no containers.
`$rc = Invoke-DockerSafe -Arguments ('compose -f "' + `$ComposeFile + '" --profile certbot run certbot renew --quiet')
if (`$rc -ne 0) { throw "Certbot renewal failed with Docker exit code `$rc." }

`$rc = Invoke-DockerSafe -Arguments ('compose -f "' + `$ComposeFile + '" exec -T frontend nginx -s reload')
if (`$rc -ne 0) { throw "Certificate renewal completed, but Nginx reload failed with Docker exit code `$rc." }
"@

$renewContent | Set-Content -Path $renewScript -Encoding UTF8
Write-Ok "Renewal script written to $renewScript"

Write-Step "19. Create a Windows Scheduled Task to renew every 12 hours"

$taskName = "RAG-IP-Certificate-Renewal"
$taskRun = "powershell.exe -NoProfile -ExecutionPolicy Bypass -File `"$renewScript`""

try {
    $schtasks = Join-Path $env:SystemRoot "System32\schtasks.exe"
    $schtaskArgs = "/Create /TN `"$taskName`" /SC HOURLY /MO 12 /TR `"$taskRun`" /RL HIGHEST /F"
    $taskProcess = Start-Process -FilePath $schtasks -ArgumentList $schtaskArgs -NoNewWindow -Wait -PassThru
    if ($taskProcess.ExitCode -eq 0) {
        Write-Ok "Scheduled task '$taskName' created"
    }
    else {
        Write-WarnMsg "Scheduled task creation returned exit code $($taskProcess.ExitCode). Create the task manually if necessary."
    }
}
catch {
    Write-WarnMsg "Could not create scheduled task: $($_.Exception.Message)"
}

Write-Step "20. Final verification"

Write-Host "`nExpected Windows configuration:"
Write-Host "  Interface      : $WiFiAlias"
Write-Host "  LAN IP         : $ServerIP/$PrefixLength"
Write-Host "  Gateway        : $Gateway"
Write-Host "  Public IP      : $PublicIP"
Write-Host "  Public HTTP    : TCP 80 -> $ServerIP`:80"
Write-Host "  Public HTTPS   : TCP 443 -> $ServerIP`:443"
Write-Host "  Application URL: https://$PublicIP"

Write-Host "`nCurrent default routes:"
Get-NetRoute -AddressFamily IPv4 -DestinationPrefix "0.0.0.0/0" -ErrorAction SilentlyContinue |
    Sort-Object RouteMetric |
    Format-Table ifIndex,InterfaceAlias,NextHop,RouteMetric,PolicyStore

Write-Host "`nCurrent relevant listeners:"
Get-NetTCPConnection -State Listen -ErrorAction SilentlyContinue |
    Where-Object { $_.LocalPort -in 80,443,8080,8443 } |
    Sort-Object LocalPort |
    Format-Table LocalAddress,LocalPort,OwningProcess

Write-Host "`nTest from a phone using MOBILE DATA (Wi-Fi off):" -ForegroundColor Yellow
Write-Host "  https://$PublicIP" -ForegroundColor Yellow
Write-Host "`nIf it works on mobile data but not from the same Wi-Fi, the router likely does not support NAT loopback/hairpin access." -ForegroundColor Yellow

Write-Ok "Setup script completed"
