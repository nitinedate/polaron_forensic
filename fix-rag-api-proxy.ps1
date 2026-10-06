[CmdletBinding()]
param(
    [string]$ProjectRoot = "F:\rag_new2",
    [string]$ComposeFile = ".\docker-compose.https.yml",
    [string]$PublicIP = "122.170.114.36",
    [int]$ApiWaitSeconds = 180
)

$ErrorActionPreference = "Stop"
$ProgressPreference = "SilentlyContinue"

# Preserve all existing/orphan containers. This script never calls compose down,
# docker rm, compose rm, --remove-orphans, volume rm, or prune.
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

function Get-DockerExe {
    $cmd = Get-Command docker.exe -ErrorAction SilentlyContinue
    if (-not $cmd) { $cmd = Get-Command docker -ErrorAction SilentlyContinue }
    if (-not $cmd) { throw "Docker CLI was not found. Start Docker Desktop and rerun this script." }
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
            return [pscustomobject]@{ ExitCode = [int]$p.ExitCode; StdOut = $stdout; StdErr = $stderr }
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
        if ($CaptureOutput -and $r.StdOut) { Write-Host $r.StdOut.TrimEnd() }
        if ($CaptureOutput -and $r.StdErr) { Write-Host $r.StdErr.TrimEnd() -ForegroundColor Yellow }
        throw "Docker command failed with exit code $($r.ExitCode): docker $Arguments"
    }
    return $r
}

function Write-Utf8NoBom {
    param([string]$Path,[string]$Text)
    $enc = New-Object System.Text.UTF8Encoding($false)
    [System.IO.File]::WriteAllText($Path, $Text, $enc)
}

function Test-HttpUrl {
    param([string]$Url,[int]$TimeoutSec = 5)
    try {
        $req = [System.Net.HttpWebRequest]::Create($Url)
        $req.Method = "GET"
        $req.Timeout = $TimeoutSec * 1000
        $req.ReadWriteTimeout = $TimeoutSec * 1000
        $req.AllowAutoRedirect = $false
        $resp = $req.GetResponse()
        $code = [int]$resp.StatusCode
        $resp.Close()
        return [pscustomobject]@{ Ok = $true; StatusCode = $code; Error = "" }
    }
    catch [System.Net.WebException] {
        if ($_.Exception.Response) {
            $code = [int]$_.Exception.Response.StatusCode
            $_.Exception.Response.Close()
            # Any HTTP response proves the TCP/HTTP path is alive. 5xx is not healthy.
            return [pscustomobject]@{ Ok = ($code -lt 500); StatusCode = $code; Error = $_.Exception.Message }
        }
        return [pscustomobject]@{ Ok = $false; StatusCode = 0; Error = $_.Exception.Message }
    }
}

function Get-ComposePath {
    param([string]$Root,[string]$Value)
    if ([System.IO.Path]::IsPathRooted($Value)) { return $Value }
    return (Join-Path $Root $Value)
}

function Show-ApiDiagnostics {
    param([string]$ComposePath)
    Write-Host "`nAPI/container diagnostics:" -ForegroundColor Yellow
    $null = Invoke-Docker -Arguments "compose -f `"$ComposePath`" ps -a api frontend" -AllowFailure
    $null = Invoke-Docker -Arguments "compose -f `"$ComposePath`" logs --tail=200 api" -AllowFailure
}

Write-Step "1. Validate project and Docker Compose"

if (-not (Test-Path $ProjectRoot)) { throw "Project root not found: $ProjectRoot" }
Set-Location $ProjectRoot

$composePath = Get-ComposePath -Root $ProjectRoot -Value $ComposeFile
if (-not (Test-Path $composePath)) { throw "Compose file not found: $composePath" }
$composePath = (Resolve-Path $composePath).Path

$configCheck = Invoke-Docker -Arguments "compose -f `"$composePath`" config --quiet" -CaptureOutput -QuietStderr -AllowFailure
if ($configCheck.ExitCode -ne 0) {
    Write-Host $configCheck.StdOut
    Write-Host $configCheck.StdErr -ForegroundColor Yellow
    throw "Docker Compose configuration is invalid. No changes were made to containers."
}
Write-Ok "Compose configuration is valid: $composePath"

$services = Invoke-Docker -Arguments "compose -f `"$composePath`" config --services" -CaptureOutput -QuietStderr
$serviceList = @($services.StdOut -split "`r?`n" | Where-Object { $_.Trim() })
foreach ($required in @("api","frontend")) {
    if ($serviceList -notcontains $required) { throw "Required Compose service '$required' is missing." }
}
Write-Ok "Required services api + frontend are present"

Write-Step "2. Repair the host-mounted Nginx production proxy"

$nginxPath = Join-Path $ProjectRoot "deployment\windows-ip-https\nginx.https.conf"
if (-not (Test-Path $nginxPath)) {
    New-Item -ItemType Directory -Force -Path (Split-Path -Parent $nginxPath) | Out-Null
    $nginx = @'
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
        set $api_upstream http://api:8080;
        proxy_pass $api_upstream;
        proxy_http_version 1.1;
        proxy_pass_request_headers on;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
        proxy_set_header X-Forwarded-Host $host;
        proxy_set_header X-Forwarded-Port $server_port;
        proxy_set_header Authorization $http_authorization;
        proxy_set_header Cookie $http_cookie;
        proxy_set_header Upgrade $http_upgrade;
        proxy_set_header Connection "upgrade";
        proxy_connect_timeout 30s;
        proxy_send_timeout 3600s;
        proxy_read_timeout 3600s;
        proxy_buffering off;
        proxy_cache off;
        proxy_next_upstream error timeout invalid_header http_502 http_503 http_504;
        proxy_next_upstream_tries 2;
    }

    location /assets/ {
        expires 1y;
        add_header Cache-Control "public, immutable";
        try_files $uri =404;
    }

    location / {
        add_header Cache-Control "no-store, no-cache, must-revalidate";
        expires -1;
        try_files $uri $uri/ /index.html;
    }
}
'@
    $nginx = $nginx.Replace("__PUBLIC_IP__", $PublicIP)
    Write-Utf8NoBom -Path $nginxPath -Text $nginx
    Write-Ok "Created production Nginx config without UTF-8 BOM"
}
else {
    $stamp = Get-Date -Format "yyyyMMdd-HHmmss"
    $backupDir = Join-Path $ProjectRoot "deployment\windows-ip-https\backups"
    New-Item -ItemType Directory -Force -Path $backupDir | Out-Null
    $backupPath = Join-Path $backupDir "nginx.https.conf.$stamp.bak"
    Copy-Item $nginxPath $backupPath -Force

    $nginx = [System.IO.File]::ReadAllText($nginxPath)
    if ($nginx.Length -gt 0 -and $nginx[0] -eq [char]0xFEFF) { $nginx = $nginx.Substring(1) }

    # Remove any accidental localhost proxy target. Inside the frontend container,
    # localhost is nginx itself; the FastAPI service is named 'api'.
    $nginx = $nginx -replace 'proxy_pass\s+http://(?:127\.0\.0\.1|localhost):8080\s*;', 'proxy_pass http://api:8080;'

    # Docker containers can receive a new IP after restart/recreate. Use a variable
    # so nginx consults Docker DNS (127.0.0.11) at request time instead of pinning
    # an old api container address at nginx startup.
    if ($nginx -match 'proxy_pass\s+http://api:8080\s*;') {
        $nginx = $nginx -replace 'proxy_pass\s+http://api:8080\s*;', "set `$api_upstream http://api:8080;`r`n        proxy_pass `$api_upstream;"
    }

    # Add Docker DNS resolver if not already present.
    if ($nginx -notmatch '(?m)^\s*resolver\s+127\.0\.0\.11\b') {
        $nginx = "resolver 127.0.0.11 valid=10s ipv6=off;`r`n`r`n" + $nginx
    }

    # Avoid stale index.html keeping an older bundle/error message in the browser.
    if (($nginx -match 'location\s+/\s*\{') -and ($nginx -notmatch 'no-store, no-cache, must-revalidate')) {
        $cacheReplacement = '$1' + "`r`n        add_header Cache-Control `"no-store, no-cache, must-revalidate`";`r`n        expires -1;"
        $nginx = $nginx -replace '(location\s+/\s*\{)', $cacheReplacement
    }

    Write-Utf8NoBom -Path $nginxPath -Text $nginx
    Write-Ok "Patched Nginx proxy and rewrote UTF-8 without BOM"
    Write-Host "Backup: $backupPath" -ForegroundColor DarkGray
}

Write-Step "3. Verify the effective proxy target"
$nginxText = [System.IO.File]::ReadAllText($nginxPath)
if ($nginxText -match 'proxy_pass\s+http://(?:127\.0\.0\.1|localhost):8080') {
    throw "Nginx still contains a localhost:8080 API proxy. Repair did not complete."
}
if (($nginxText -notmatch 'proxy_pass\s+\$api_upstream') -and ($nginxText -notmatch 'proxy_pass\s+http://api:8080')) {
    throw "No Nginx proxy to api:8080 was found in $nginxPath"
}
Write-Ok "Nginx /api target points to Docker service api:8080"

Write-Step "4. Ensure FastAPI is running and healthy"
$startApi = Invoke-Docker -Arguments "compose -f `"$composePath`" up -d api" -CaptureOutput -QuietStderr -AllowFailure
if ($startApi.ExitCode -ne 0) {
    Write-Host $startApi.StdOut
    Write-Host $startApi.StdErr -ForegroundColor Yellow
    Show-ApiDiagnostics -ComposePath $composePath
    throw "Could not start/confirm the api service."
}

$deadline = (Get-Date).AddSeconds($ApiWaitSeconds)
$apiHealthy = $false
$lastHealth = $null
while ((Get-Date) -lt $deadline) {
    $lastHealth = Test-HttpUrl -Url "http://127.0.0.1:8080/health" -TimeoutSec 5
    if ($lastHealth.Ok -and $lastHealth.StatusCode -ge 200 -and $lastHealth.StatusCode -lt 500) {
        $apiHealthy = $true
        break
    }
    Start-Sleep -Seconds 5
}

if (-not $apiHealthy) {
    Show-ApiDiagnostics -ComposePath $composePath
    throw "FastAPI did not become reachable on http://127.0.0.1:8080/health. Last error: $($lastHealth.Error)"
}
Write-Ok "FastAPI responds on 127.0.0.1:8080/health (HTTP $($lastHealth.StatusCode))"

Write-Step "5. Restart frontend only so Nginx reloads Docker DNS and the repaired config"
# restart does NOT remove or recreate the container.
$restart = Invoke-Docker -Arguments "compose -f `"$composePath`" restart frontend" -CaptureOutput -QuietStderr -AllowFailure
if ($restart.ExitCode -ne 0) {
    Write-Host $restart.StdOut
    Write-Host $restart.StdErr -ForegroundColor Yellow
    throw "Frontend restart failed. No container was removed."
}
Start-Sleep -Seconds 5
Write-Ok "Frontend restarted without removing/recreating it"

Write-Step "6. Validate Nginx syntax"
$nginxTest = Invoke-Docker -Arguments "compose -f `"$composePath`" exec -T frontend nginx -t" -CaptureOutput -QuietStderr -AllowFailure
if ($nginxTest.ExitCode -ne 0) {
    Write-Host $nginxTest.StdOut
    Write-Host $nginxTest.StdErr -ForegroundColor Yellow
    throw "Nginx configuration test failed (Docker exit code $($nginxTest.ExitCode))."
}
Write-Ok "nginx -t passed"

Write-Step "7. Verify frontend container can reach api:8080"
$inside = Invoke-Docker -Arguments "compose -f `"$composePath`" exec -T frontend wget -q -S -O- http://api:8080/health" -CaptureOutput -QuietStderr -AllowFailure
if ($inside.ExitCode -ne 0) {
    Write-Host $inside.StdOut
    Write-Host $inside.StdErr -ForegroundColor Yellow
    Show-ApiDiagnostics -ComposePath $composePath
    throw "Frontend container cannot reach http://api:8080/health. Check Docker networking/API state."
}
Write-Host $inside.StdOut.TrimEnd()
Write-Ok "frontend -> api:8080 connectivity works"

Write-Step "8. Verify HTTPS /api through Nginx"
$curl = Get-Command curl.exe -ErrorAction SilentlyContinue
if ($curl) {
    $curlArgs = "-k -sS -o NUL -w `"%{http_code}`" https://127.0.0.1/api/health"
    $proxy = Invoke-NativeProcess -FilePath $curl.Source -Arguments $curlArgs -CaptureOutput -QuietStderr
    $statusText = $proxy.StdOut.Trim()
    $statusCode = 0
    [void][int]::TryParse($statusText, [ref]$statusCode)

    if ($proxy.ExitCode -ne 0) {
        Write-WarnMsg "Local HTTPS request could not be completed: $($proxy.StdErr.Trim())"
    }
    elseif ($statusCode -ge 500 -or $statusCode -eq 0) {
        Write-WarnMsg "Nginx returned HTTP $statusCode for /api/health. Showing frontend logs."
        $null = Invoke-Docker -Arguments "compose -f `"$composePath`" logs --tail=150 frontend" -AllowFailure
    }
    else {
        Write-Ok "HTTPS /api path is reaching the backend (HTTP $statusCode)"
    }
}
else {
    Write-WarnMsg "curl.exe was not found; skipped local HTTPS request."
}

Write-Step "9. Check for the stale Vite-development error text"
$staleText = "Unable to reach the API server via the Vite dev proxy"
$frontendRoot = Join-Path $ProjectRoot "frontend"
$matches = @()
if (Test-Path $frontendRoot) {
    $candidateFiles = Get-ChildItem $frontendRoot -Recurse -File -ErrorAction SilentlyContinue |
        Where-Object {
            $_.FullName -notmatch '[\\/](node_modules|dist|build|\.git)[\\/]' -and
            $_.Extension -in @('.js','.jsx','.ts','.tsx','.mjs','.cjs','.html')
        }
    foreach ($file in $candidateFiles) {
        try {
            $text = [System.IO.File]::ReadAllText($file.FullName)
            if ($text.Contains($staleText)) { $matches += $file.FullName }
        }
        catch { }
    }
}

if ($matches.Count -gt 0) {
    Write-WarnMsg "The frontend source still contains a misleading Vite-dev error message. It is cosmetic in the Nginx production deployment. Files:"
    $matches | ForEach-Object { Write-Host "  $_" -ForegroundColor Yellow }
    Write-Host "The functional proxy has been repaired without rebuilding/recreating the frontend container." -ForegroundColor Yellow
}
else {
    Write-Ok "No matching stale Vite-dev error text was found in frontend source"
}

Write-Step "10. Final status"
$null = Invoke-Docker -Arguments "compose -f `"$composePath`" ps api frontend" -AllowFailure

Write-Host "`nRepair complete." -ForegroundColor Green
Write-Host "Local API:    http://127.0.0.1:8080/health"
Write-Host "Local HTTPS:  https://127.0.0.1/api/health"
Write-Host "Public HTTPS: https://$PublicIP/api/health"
Write-Host "Application:  https://$PublicIP"
Write-Host "`nIf the browser still shows the old Vite-proxy message after all checks pass, press Ctrl+Shift+R once to force-refresh the cached index/bundle." -ForegroundColor Cyan
