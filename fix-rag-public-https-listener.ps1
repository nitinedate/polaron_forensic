[CmdletBinding()]
param(
    [string]$ProjectRoot = "F:\rag_new2",
    [string]$ComposeFile = ".\docker-compose.https.yml",
    [string]$PublicIP = "122.170.114.36",
    [string]$FrontendImage = "rag_new2-frontend"
)

$ErrorActionPreference = "Stop"
$ProgressPreference = "SilentlyContinue"

# Non-destructive policy:
# - never docker compose down
# - never docker rm / compose rm
# - never --remove-orphans
# - never prune or delete volumes
# The existing frontend container is deliberately left untouched.
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
    Write-Host "[WARN] $Message" -ForegroundColor Yellow
}

function Get-DockerExe {
    $cmd = Get-Command docker.exe -ErrorAction SilentlyContinue
    if (-not $cmd) { $cmd = Get-Command docker -ErrorAction SilentlyContinue }
    if (-not $cmd) { throw "Docker CLI was not found. Start Docker Desktop and rerun." }
    return $cmd.Source
}

function Invoke-NativeProcess {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$true)][string]$FilePath,
        [Parameter(Mandatory=$true)][string]$Arguments,
        [switch]$CaptureOutput,
        [switch]$QuietStderr
    )

    if ($CaptureOutput) {
        $stdoutFile = [System.IO.Path]::GetTempFileName()
        $stderrFile = [System.IO.Path]::GetTempFileName()
        try {
            $p = Start-Process -FilePath $FilePath -ArgumentList $Arguments -NoNewWindow -Wait -PassThru `
                -RedirectStandardOutput $stdoutFile -RedirectStandardError $stderrFile

            $stdout = if (Test-Path $stdoutFile) { [System.IO.File]::ReadAllText($stdoutFile) } else { "" }
            $stderr = if (Test-Path $stderrFile) { [System.IO.File]::ReadAllText($stderrFile) } else { "" }

            if ((-not $QuietStderr) -and (-not [string]::IsNullOrWhiteSpace($stderr))) {
                Write-Host $stderr.TrimEnd() -ForegroundColor DarkGray
            }

            return [pscustomobject]@{
                ExitCode = [int]$p.ExitCode
                StdOut   = $stdout
                StdErr   = $stderr
            }
        }
        finally {
            Remove-Item $stdoutFile,$stderrFile -Force -ErrorAction SilentlyContinue
        }
    }

    $p = Start-Process -FilePath $FilePath -ArgumentList $Arguments -NoNewWindow -Wait -PassThru
    return [pscustomobject]@{ ExitCode = [int]$p.ExitCode; StdOut = ""; StdErr = "" }
}

$script:DockerExe = Get-DockerExe

function Invoke-Docker {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$true)][string]$Arguments,
        [switch]$CaptureOutput,
        [switch]$QuietStderr,
        [switch]$AllowFailure
    )

    $r = Invoke-NativeProcess -FilePath $script:DockerExe -Arguments $Arguments -CaptureOutput:$CaptureOutput -QuietStderr:$QuietStderr
    if (($r.ExitCode -ne 0) -and (-not $AllowFailure)) {
        if ($CaptureOutput -and -not [string]::IsNullOrWhiteSpace($r.StdOut)) { Write-Host $r.StdOut.TrimEnd() }
        if ($CaptureOutput -and -not [string]::IsNullOrWhiteSpace($r.StdErr)) { Write-Host $r.StdErr.TrimEnd() -ForegroundColor Yellow }
        throw "Docker command failed with exit code $($r.ExitCode): docker $Arguments"
    }
    return $r
}

function Write-Utf8NoBom {
    param([string]$Path,[string]$Text)
    $enc = New-Object System.Text.UTF8Encoding($false)
    [System.IO.File]::WriteAllText($Path, $Text, $enc)
}

function Resolve-ComposePath {
    param([string]$Root,[string]$Value)
    if ([System.IO.Path]::IsPathRooted($Value)) { return $Value }
    return (Join-Path $Root $Value)
}

function Get-ListeningOwners {
    param([int]$Port)
    try {
        return @(Get-NetTCPConnection -State Listen -LocalPort $Port -ErrorAction SilentlyContinue)
    }
    catch {
        return @()
    }
}

function Test-HttpsEndpoint {
    param([string]$Url)
    $curl = Get-Command curl.exe -ErrorAction SilentlyContinue
    if (-not $curl) {
        return [pscustomobject]@{ ExitCode = 999; StdOut = ""; StdErr = "curl.exe not found" }
    }
    return Invoke-NativeProcess -FilePath $curl.Source -Arguments "-k -sS -o NUL -w `"%{http_code}`" `"$Url`"" -CaptureOutput -QuietStderr
}

Write-Step "1. Validate project, Compose, image, and current frontend"

if (-not (Test-Path $ProjectRoot)) { throw "Project root not found: $ProjectRoot" }
Set-Location $ProjectRoot

$composePath = Resolve-ComposePath -Root $ProjectRoot -Value $ComposeFile
if (-not (Test-Path $composePath)) { throw "Compose file not found: $composePath" }
$composePath = (Resolve-Path $composePath).Path

$config = Invoke-Docker -Arguments "compose -f `"$composePath`" config --quiet" -CaptureOutput -QuietStderr -AllowFailure
if ($config.ExitCode -ne 0) {
    Write-Host $config.StdOut
    Write-Host $config.StdErr -ForegroundColor Yellow
    throw "Compose configuration is invalid. No container changes were made."
}
Write-Ok "Compose configuration is valid"

$services = Invoke-Docker -Arguments "compose -f `"$composePath`" config --services" -CaptureOutput -QuietStderr
$serviceList = @($services.StdOut -split "`r?`n" | Where-Object { $_.Trim() })
foreach ($required in @("api","frontend")) {
    if ($serviceList -notcontains $required) { throw "Required Compose service '$required' is missing." }
}
Write-Ok "Required services api + frontend are present"

$imageCheck = Invoke-Docker -Arguments "image inspect $FrontendImage" -CaptureOutput -QuietStderr -AllowFailure
if ($imageCheck.ExitCode -ne 0) {
    Write-WarnMsg "Frontend image '$FrontendImage' is missing. Building the existing frontend service image first."
    $null = Invoke-Docker -Arguments "compose -f `"$composePath`" build frontend"
}
Write-Ok "Frontend image is available: $FrontendImage"

Write-Host "`nExisting frontend status (left untouched):" -ForegroundColor Gray
$null = Invoke-Docker -Arguments "compose -f `"$composePath`" ps -a frontend" -AllowFailure

Write-Step "2. Verify host ports 80 and 443 are available"

$port80 = Get-ListeningOwners -Port 80
$port443 = Get-ListeningOwners -Port 443

if ($port80.Count -gt 0) {
    Write-Host "Port 80 already has a listener:" -ForegroundColor Yellow
    $port80 | Format-Table LocalAddress,LocalPort,OwningProcess -AutoSize
}
if ($port443.Count -gt 0) {
    Write-Host "Port 443 already has a listener:" -ForegroundColor Yellow
    $port443 | Format-Table LocalAddress,LocalPort,OwningProcess -AutoSize
}

if (($port80.Count -gt 0) -or ($port443.Count -gt 0)) {
    Write-Host "`nDocker containers currently publishing 80/443:" -ForegroundColor Yellow
    $null = Invoke-Docker -Arguments "ps --format `"table {{.Names}}`t{{.Ports}}`"" -AllowFailure
    throw "Host port 80 and/or 443 is already occupied. This script will not stop or remove the existing owner."
}

Write-Ok "Host ports 80 and 443 are free"

Write-Step "3. Validate production Nginx config and certificate paths"

$nginxPath = Join-Path $ProjectRoot "deployment\windows-ip-https\nginx.https.conf"
if (-not (Test-Path $nginxPath)) { throw "Nginx config not found: $nginxPath" }

$nginxText = [System.IO.File]::ReadAllText($nginxPath)
if ($nginxText.Length -gt 0 -and $nginxText[0] -eq [char]0xFEFF) {
    $nginxText = $nginxText.Substring(1)
    Write-Utf8NoBom -Path $nginxPath -Text $nginxText
    Write-Ok "Removed UTF-8 BOM from Nginx config"
}

if ($nginxText -notmatch 'listen\s+443\s+ssl') { throw "Nginx config does not contain a TLS listener on 443." }
if ($nginxText -notmatch 'api:8080') { throw "Nginx config does not target Docker service api:8080." }
if ($nginxText -match 'proxy_pass\s+http://(?:127\.0\.0\.1|localhost):8080') {
    throw "Nginx still contains an invalid localhost:8080 API proxy target. Run fix-rag-api-proxy.ps1 first."
}
Write-Ok "Nginx TLS listener and api:8080 proxy are configured"

$certCheck = Invoke-Docker -Arguments "compose -f `"$composePath`" --profile certbot run certbot certificates" -CaptureOutput -QuietStderr -AllowFailure
$certText = $certCheck.StdOut
if (($certCheck.ExitCode -ne 0) -or ($certText -notmatch ("Certificate Name:\s*" + [regex]::Escape($PublicIP)))) {
    Write-WarnMsg "Could not confirm a production certificate named $PublicIP through Certbot."
    Write-WarnMsg "The public HTTPS container can only start if /etc/letsencrypt/live/$PublicIP/fullchain.pem and privkey.pem already exist."
}
else {
    Write-Ok "Production certificate entry found for $PublicIP"
}

Write-Step "4. Create non-destructive public-edge Compose overlay"

$overlayDir = Join-Path $ProjectRoot "deployment\windows-ip-https"
New-Item -ItemType Directory -Force -Path $overlayDir | Out-Null
$overlayPath = Join-Path $overlayDir "docker-compose.frontend-public.yml"

$overlay = @'
services:
  frontend-public:
    image: __FRONTEND_IMAGE__
    restart: unless-stopped
    ports:
      - "80:80"
      - "443:443"
    volumes:
      - ./deployment/windows-ip-https/nginx.https.conf:/etc/nginx/conf.d/default.conf:ro
      - certbot_etc:/etc/letsencrypt:ro
      - certbot_www:/var/www/certbot:ro
    depends_on:
      api:
        condition: service_healthy
'@
$overlay = $overlay.Replace("__FRONTEND_IMAGE__", $FrontendImage)
Write-Utf8NoBom -Path $overlayPath -Text $overlay
Write-Ok "Overlay written: $overlayPath"

$mergedCheck = Invoke-Docker -Arguments "compose -f `"$composePath`" -f `"$overlayPath`" config --quiet" -CaptureOutput -QuietStderr -AllowFailure
if ($mergedCheck.ExitCode -ne 0) {
    Write-Host $mergedCheck.StdOut
    Write-Host $mergedCheck.StdErr -ForegroundColor Yellow
    throw "Merged Compose configuration is invalid. Existing containers were not modified."
}
Write-Ok "Merged Compose configuration is valid"

Write-Step "5. Ensure API is healthy"

$apiStatus = Invoke-Docker -Arguments "compose -f `"$composePath`" ps -a api" -CaptureOutput -QuietStderr -AllowFailure
if ($apiStatus.StdOut) { Write-Host $apiStatus.StdOut.TrimEnd() }

$apiIdResult = Invoke-Docker -Arguments "compose -f `"$composePath`" ps -q api" -CaptureOutput -QuietStderr -AllowFailure
$apiId = $apiIdResult.StdOut.Trim()
if ([string]::IsNullOrWhiteSpace($apiId)) {
    Write-WarnMsg "API is not running; starting api without touching frontend."
    $null = Invoke-Docker -Arguments "compose -f `"$composePath`" up -d api"
    Start-Sleep -Seconds 5
}

$apiHealth = Invoke-Docker -Arguments "compose -f `"$composePath`" exec -T api python -c `"import urllib.request; print(urllib.request.urlopen('http://127.0.0.1:8080/health', timeout=5).read().decode())`"" -CaptureOutput -QuietStderr -AllowFailure
if ($apiHealth.ExitCode -ne 0) {
    Write-Host $apiHealth.StdOut
    Write-Host $apiHealth.StdErr -ForegroundColor Yellow
    throw "API health check failed. Public frontend was not started."
}
Write-Host $apiHealth.StdOut.TrimEnd()
Write-Ok "API is reachable inside its container"

Write-Step "6. Start NEW frontend-public container on 80/443"

# Important: start only the new service. No recreate/remove of existing frontend.
$startPublic = Invoke-Docker -Arguments "compose -f `"$composePath`" -f `"$overlayPath`" up -d --no-deps frontend-public" -CaptureOutput -QuietStderr -AllowFailure
if ($startPublic.StdOut) { Write-Host $startPublic.StdOut.TrimEnd() }
if ($startPublic.StdErr) { Write-Host $startPublic.StdErr.TrimEnd() -ForegroundColor DarkGray }
if ($startPublic.ExitCode -ne 0) {
    throw "frontend-public failed to start (Docker exit code $($startPublic.ExitCode)). Existing frontend was not removed."
}

Start-Sleep -Seconds 5
Write-Ok "frontend-public was started; existing frontend remains untouched"

Write-Step "7. Validate frontend-public and Nginx"

$null = Invoke-Docker -Arguments "compose -f `"$composePath`" -f `"$overlayPath`" ps -a frontend-public" -AllowFailure

$nginxTest = Invoke-Docker -Arguments "compose -f `"$composePath`" -f `"$overlayPath`" exec -T frontend-public nginx -t" -CaptureOutput -QuietStderr -AllowFailure
if ($nginxTest.StdOut) { Write-Host $nginxTest.StdOut.TrimEnd() }
if ($nginxTest.StdErr) { Write-Host $nginxTest.StdErr.TrimEnd() -ForegroundColor DarkGray }
if ($nginxTest.ExitCode -ne 0) {
    $null = Invoke-Docker -Arguments "compose -f `"$composePath`" -f `"$overlayPath`" logs --tail=150 frontend-public" -AllowFailure
    throw "frontend-public Nginx validation failed."
}
Write-Ok "frontend-public nginx -t passed"

$apiFromEdge = Invoke-Docker -Arguments "compose -f `"$composePath`" -f `"$overlayPath`" exec -T frontend-public sh -c `"wget -qO- http://api:8080/health`"" -CaptureOutput -QuietStderr -AllowFailure
if ($apiFromEdge.ExitCode -ne 0) {
    Write-Host $apiFromEdge.StdOut
    Write-Host $apiFromEdge.StdErr -ForegroundColor Yellow
    throw "frontend-public cannot reach api:8080 over the Compose network."
}
Write-Host $apiFromEdge.StdOut.TrimEnd()
Write-Ok "frontend-public -> api:8080 connectivity works"

Write-Step "8. Verify Windows listeners and local HTTPS"

Start-Sleep -Seconds 2
$now80 = Get-ListeningOwners -Port 80
$now443 = Get-ListeningOwners -Port 443

if ($now80.Count -gt 0) {
    Write-Ok "Host port 80 is listening"
} else {
    Write-WarnMsg "Host port 80 is still not listening"
}

if ($now443.Count -gt 0) {
    Write-Ok "Host port 443 is listening"
} else {
    Write-WarnMsg "Host port 443 is still not listening"
}

$httpsLocal = Test-HttpsEndpoint -Url "https://127.0.0.1/api/health"
$httpCode = $httpsLocal.StdOut.Trim()
if (($httpsLocal.ExitCode -eq 0) -and ($httpCode -match '^2\d\d$')) {
    Write-Ok "https://127.0.0.1/api/health returned HTTP $httpCode"
}
elseif (($httpsLocal.ExitCode -eq 0) -and ($httpCode -match '^\d{3}$')) {
    Write-WarnMsg "Local HTTPS is reachable but /api/health returned HTTP $httpCode"
}
else {
    Write-WarnMsg "Local HTTPS test failed: $($httpsLocal.StdErr.Trim())"
}

Write-Step "9. Final status"

Write-Host "Existing frontend (preserved):" -ForegroundColor Gray
$null = Invoke-Docker -Arguments "compose -f `"$composePath`" ps -a frontend" -AllowFailure

Write-Host "`nNew public frontend:" -ForegroundColor Gray
$null = Invoke-Docker -Arguments "compose -f `"$composePath`" -f `"$overlayPath`" ps -a frontend-public" -AllowFailure

Write-Host "`nPublished Docker ports:" -ForegroundColor Gray
$null = Invoke-Docker -Arguments "ps --format `"table {{.Names}}`t{{.Ports}}`"" -AllowFailure

Write-Host "`nPublic HTTPS listener repair complete." -ForegroundColor Green
Write-Host "Local test:   https://127.0.0.1/api/health"
Write-Host "Public API:   https://$PublicIP/api/health"
Write-Host "Application:  https://$PublicIP"
Write-Host "`nNo existing containers or volumes were removed by this script." -ForegroundColor Green
Write-Host "If local HTTPS works but the public IP does not, the remaining issue is Windows Firewall or Airtel port forwarding/NAT." -ForegroundColor Yellow
