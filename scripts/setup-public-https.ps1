<#
.SYNOPSIS
  Expose Aetheris on https://122.179.141.248 (TCP 80/443) via aetheris-gateway.

.DESCRIPTION
  - Opens Windows Firewall for TCP 80 and 443
  - Optionally verifies LAN IP 192.168.1.16 is present
  - Issues a Let's Encrypt short-lived IP certificate for 122.179.141.248
    (or installs a self-signed cert with -SelfSigned)
  - Starts aetheris-gateway with public HTTPS bindings on 80/443
  - Leaves :3000/:3001 available for local LAN use

  Router requirement (manual):
    WAN 122.179.141.248 TCP 80  →  LAN 192.168.1.16:80
    WAN 122.179.141.248 TCP 443 →  LAN 192.168.1.16:443

.EXAMPLE
  # Administrator PowerShell, from repo root:
  powershell -NoProfile -ExecutionPolicy Bypass -File .\scripts\setup-public-https.ps1 -Email you@example.com

.EXAMPLE
  # Trusted certificate for the public domain (removes the Chrome warning):
  powershell -NoProfile -ExecutionPolicy Bypass -File .\scripts\setup-public-https.ps1 -Domain future-softtech.co.in -Email you@example.com -LanIP 192.168.1.9 -PublicIP 122.179.140.167 -ForceRecreate

.EXAMPLE
  # Offline / no LE yet — self-signed (browsers will warn):
  powershell -NoProfile -ExecutionPolicy Bypass -File .\scripts\setup-public-https.ps1 -SelfSigned
#>
[CmdletBinding()]
param(
    [string]$ProjectRoot = "",
    [string]$PublicIP = "122.179.141.248",
    [string]$LanIP = "192.168.1.16",
    [string]$Domain = "",
    [string]$Email = "",
    [switch]$SelfSigned,
    [switch]$Staging,
    [switch]$SkipFirewall,
    [switch]$SkipCert,
    [switch]$SkipLanCheck,
    [switch]$ForceRecreate
)

$ErrorActionPreference = "Stop"
$ProgressPreference = "SilentlyContinue"
$env:COMPOSE_IGNORE_ORPHANS = "true"
$env:COMPOSE_REMOVE_ORPHANS = "false"
$env:COMPOSE_PROGRESS = "plain"
$env:DOCKER_CLI_HINTS = "false"

function Write-Step([string]$Message) {
    Write-Host ""
    Write-Host ("==== {0} ====" -f $Message) -ForegroundColor Cyan
}

function Write-Ok([string]$Message) {
    Write-Host ("[OK] {0}" -f $Message) -ForegroundColor Green
}

function Write-WarnMsg([string]$Message) {
    Write-Warning $Message
}

function Assert-Administrator {
    $identity = [Security.Principal.WindowsIdentity]::GetCurrent()
    $principal = New-Object Security.Principal.WindowsPrincipal($identity)
    if (-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
        throw "Run PowerShell as Administrator, then re-run this script."
    }
}

function Get-DockerExe {
    $cmd = Get-Command docker.exe -ErrorAction SilentlyContinue
    if (-not $cmd) { $cmd = Get-Command docker -ErrorAction SilentlyContinue }
    if (-not $cmd) { throw "Docker CLI was not found. Start Docker Desktop first." }
    return $cmd.Source
}

function Invoke-DockerExit {
    param([Parameter(Mandatory = $true)][string[]]$ArgumentList)
    $docker = Get-DockerExe
    # Windows PowerShell 5.1 splits array arguments that contain spaces, so a
    # multiline "sh -c" script becomes just "set" and exits 0 without writing a cert.
    # Pass one quoted command line instead.
    $quoted = foreach ($arg in $ArgumentList) {
        if ($arg -match '[\s"]') { '"' + ($arg.Replace('"', '\"')) + '"' } else { $arg }
    }
    $line = $quoted -join ' '
    $out = Join-Path $env:TEMP "aetheris-docker-out.txt"
    $err = Join-Path $env:TEMP "aetheris-docker-err.txt"
    $p = Start-Process -FilePath $docker -ArgumentList $line -NoNewWindow -Wait -PassThru `
        -RedirectStandardOutput $out -RedirectStandardError $err
    $script:LastDockerOutput = @()
    if (Test-Path $out) { $script:LastDockerOutput += @(Get-Content -LiteralPath $out -ErrorAction SilentlyContinue) }
    if (Test-Path $err) { $script:LastDockerOutput += @(Get-Content -LiteralPath $err -ErrorAction SilentlyContinue) }
    return [int]$p.ExitCode
}

function Invoke-Docker {
    param(
        [Parameter(Mandatory = $true)][string[]]$ArgumentList,
        [string]$FailureMessage = "Docker command failed"
    )
    $rc = Invoke-DockerExit -ArgumentList $ArgumentList
    if ($rc -ne 0) {
        if ($script:LastDockerOutput) { $script:LastDockerOutput | ForEach-Object { Write-Host $_ } }
        throw ("{0} (exit {1}). Args: docker {2}" -f $FailureMessage, $rc, ($ArgumentList -join ' '))
    }
}

function Ensure-FirewallRule {
    param([string]$Name, [int]$Port)
    $existing = Get-NetFirewallRule -DisplayName $Name -ErrorAction SilentlyContinue
    if ($existing) {
        $existing | Set-NetFirewallRule -Enabled True -Direction Inbound -Action Allow -Profile Any | Out-Null
        Write-Ok "Firewall rule enabled: $Name (TCP $Port)"
        return
    }
    New-NetFirewallRule `
        -DisplayName $Name `
        -Direction Inbound `
        -Action Allow `
        -Protocol TCP `
        -LocalPort $Port `
        -Profile Any | Out-Null
    Write-Ok "Firewall rule created: $Name (TCP $Port)"
}

function Assert-LanIp {
    param([string]$Expected)
    $addrs = @(Get-NetIPAddress -AddressFamily IPv4 -ErrorAction SilentlyContinue |
        Where-Object { $_.IPAddress -eq $Expected })
    if (-not $addrs.Count) {
        throw ("LAN IP {0} was not found on this machine. Assign it on the Airtel NIC, or pass -SkipLanCheck." -f $Expected)
    }
    Write-Ok ("LAN IP present: {0}" -f $Expected)
}

function Get-ComposeArgs {
    param([string]$Root)
    return @(
        "compose",
        "--project-directory", $Root,
        "--project-name", "aetheris-gateway",
        "-f", "services/gateway/docker-compose.yml",
        "-f", "deployment/windows-ip-https/docker-compose.gateway-public-https.yml"
    )
}

function Write-Utf8File {
    param([string]$Path, [string]$Text)
    $dir = Split-Path -Parent $Path
    if (-not (Test-Path -LiteralPath $dir)) {
        New-Item -ItemType Directory -Path $dir -Force | Out-Null
    }
    [System.IO.File]::WriteAllText($Path, $Text.Replace("`r`n", "`n").Replace("`n", "`r`n"), [System.Text.UTF8Encoding]::new($false))
}

function Get-BundledNginxHttpsConfig {
    param([string]$PublicIP)
    $text = @'
# Public HTTPS edge for aetheris-gateway.
# Written by scripts/setup-public-https.ps1 when the deployment file is missing.
resolver 127.0.0.11 valid=10s ipv6=off;

map $http_x_aetheris_service $hdr_upstream {
    default                         http://host.docker.internal:8083;
    forensic                        http://host.docker.internal:8083;
    mobile-android                  http://host.docker.internal:8081;
    android                         http://host.docker.internal:8081;
    mobile-ios                      http://host.docker.internal:8084;
    ios                             http://host.docker.internal:8084;
    mobile-extract                  http://host.docker.internal:8081;
    mobile                          http://host.docker.internal:8081;
    vuln                            http://host.docker.internal:8082;
}

server {
    listen 80;
    listen [::]:80;
    server_name __PUBLIC_IP__ _;

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
    server_name __PUBLIC_IP__ _;

    ssl_certificate     /etc/letsencrypt/live/__PUBLIC_IP__/fullchain.pem;
    ssl_certificate_key /etc/letsencrypt/live/__PUBLIC_IP__/privkey.pem;
    ssl_protocols TLSv1.2 TLSv1.3;
    ssl_session_cache shared:SSL:10m;
    ssl_session_timeout 1d;
    ssl_prefer_server_ciphers off;

    root /usr/share/nginx/html;
    index index.html;
    server_tokens off;
    client_max_body_size 0;
    error_log /dev/stderr warn;

    location ^~ /.well-known/acme-challenge/ {
        root /var/www/certbot;
        default_type text/plain;
        try_files $uri =404;
    }

    location = /health {
        set $api_upstream http://host.docker.internal:8082;
        include /etc/nginx/conf.d/gateway-proxy.inc;
    }

    location /api/acquisition/ {
        set $api_upstream $hdr_upstream;
        include /etc/nginx/conf.d/gateway-proxy.inc;
    }

    location /api/vuln/ { set $api_upstream http://host.docker.internal:8082; include /etc/nginx/conf.d/gateway-proxy.inc; }
    location /api/scanners { set $api_upstream http://host.docker.internal:8082; include /etc/nginx/conf.d/gateway-proxy.inc; }
    location /api/scanner-agent/ { set $api_upstream http://host.docker.internal:8082; include /etc/nginx/conf.d/gateway-proxy.inc; }
    location /api/scan-jobs { set $api_upstream http://host.docker.internal:8082; include /etc/nginx/conf.d/gateway-proxy.inc; }
    location /api/scan-policies { set $api_upstream http://host.docker.internal:8082; include /etc/nginx/conf.d/gateway-proxy.inc; }
    location /api/assets { set $api_upstream http://host.docker.internal:8082; include /etc/nginx/conf.d/gateway-proxy.inc; }
    location /api/remediation-tasks { set $api_upstream http://host.docker.internal:8082; include /etc/nginx/conf.d/gateway-proxy.inc; }

    location /api/ {
        set $api_upstream $hdr_upstream;
        include /etc/nginx/conf.d/gateway-proxy.inc;
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
    return $text.Replace('__PUBLIC_IP__', $PublicIP)
}

function Ensure-PublicHttpsFiles {
    param([string]$Root, [string]$PublicIP, [string]$CertName)
    if (-not $CertName) { $CertName = $PublicIP }
    $deploy = Join-Path $Root "deployment\windows-ip-https"
    $nginxPath = Join-Path $deploy "nginx.gateway.https.conf"
    if (Test-Path -LiteralPath $nginxPath) {
        $text = [System.IO.File]::ReadAllText($nginxPath)
        $text = [regex]::Replace($text, '(?m)^(\s*server_name\s+)(?!_;)\S+(?:\s+_)?\s*;', { param($m) $m.Groups[1].Value + $CertName + ' _;' })
        $text = [regex]::Replace($text, '/etc/letsencrypt/live/[^/]+/', ("/etc/letsencrypt/live/{0}/" -f $CertName))
    } else {
        $text = Get-BundledNginxHttpsConfig -PublicIP $CertName
        Write-Ok "Created missing Nginx HTTPS config"
    }
    Write-Utf8File -Path $nginxPath -Text $text

    $composePath = Join-Path $deploy "docker-compose.gateway-public-https.yml"
    if (Test-Path -LiteralPath $composePath) {
        # 3002 is the Android UI. An older overlay bound it on the gateway and
        # Compose then failed with "port is already allocated".
        $composeText = [System.IO.File]::ReadAllText($composePath)
        $stripped = [regex]::Replace($composeText, '(?m)^\s*-\s*"3002:80"\s*\r?\n', '')
        if ($stripped -ne $composeText) {
            Write-Utf8File -Path $composePath -Text $stripped
            Write-Ok "Removed gateway port 3002 (already used by the Android UI)"
        }
    }
    if (-not (Test-Path -LiteralPath $composePath)) {
        Write-Utf8File -Path $composePath -Text @'
# Public HTTPS edge on top of services/gateway/docker-compose.yml.
name: aetheris-gateway

services:
  gateway:
    ports: !override
      - "80:80"
      - "443:443"
      - "3001:80"
    extra_hosts:
      - "host.docker.internal:host-gateway"
    volumes:
      - ./deployment/windows-ip-https/nginx.gateway.https.conf:/etc/nginx/conf.d/default.conf:ro
      - ./frontend/gateway-proxy.inc:/etc/nginx/conf.d/gateway-proxy.inc:ro
      - certbot_etc:/etc/letsencrypt:ro
      - certbot_www:/var/www/certbot:ro
    healthcheck:
      test: ["CMD-SHELL", "wget -q -T 3 -O /dev/null https://127.0.0.1/ --no-check-certificate || wget -q -T 3 -O /dev/null http://127.0.0.1/ || exit 1"]
      interval: 10s
      timeout: 5s
      retries: 8
      start_period: 15s

  acme-bootstrap:
    image: nginx:1.27-alpine
    profiles: ["acme-bootstrap"]
    ports:
      - "80:80"
    volumes:
      - certbot_www:/usr/share/nginx/html:ro
      - ./deployment/windows-ip-https/acme-bootstrap.default.conf:/etc/nginx/conf.d/default.conf:ro

  certbot:
    image: certbot/certbot:latest
    profiles: ["certbot"]
    volumes:
      - certbot_etc:/etc/letsencrypt
      - certbot_www:/var/www/certbot

volumes:
  certbot_etc:
  certbot_www:
'@
        Write-Ok "Created missing public HTTPS compose overlay"
    }

    $acmePath = Join-Path $deploy "acme-bootstrap.default.conf"
    if (-not (Test-Path -LiteralPath $acmePath)) {
        Write-Utf8File -Path $acmePath -Text @'
server {
    listen 80;
    listen [::]:80;
    server_name _;

    location ^~ /.well-known/acme-challenge/ {
        root /usr/share/nginx/html;
        default_type text/plain;
        try_files $uri =404;
    }

    location / {
        default_type text/plain;
        return 200 "Aetheris ACME bootstrap — waiting for certificate.\n";
    }
}
'@
        Write-Ok "Created missing ACME bootstrap config"
    }

    $proxyPath = Join-Path $Root "frontend\gateway-proxy.inc"
    if (-not (Test-Path -LiteralPath $proxyPath)) {
        Write-Utf8File -Path $proxyPath -Text @'
proxy_pass $api_upstream;
proxy_http_version 1.1;
proxy_pass_request_headers on;
proxy_set_header Host $host;
proxy_set_header X-Real-IP $remote_addr;
proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
proxy_set_header X-Forwarded-Proto $scheme;
proxy_set_header Authorization $http_authorization;
proxy_set_header X-Aetheris-Agent-Instance $http_x_aetheris_agent_instance;
proxy_set_header X-Aetheris-Service $http_x_aetheris_service;
proxy_set_header X-Tenant $http_x_tenant;
proxy_hide_header Server;
proxy_hide_header Date;
proxy_buffering off;
proxy_cache off;
proxy_connect_timeout 30s;
proxy_send_timeout 7d;
proxy_read_timeout 7d;
send_timeout 7d;
client_body_timeout 7d;
proxy_next_upstream error timeout invalid_header http_502 http_503 http_504;
proxy_next_upstream_tries 2;
'@
        Write-Ok "Created missing frontend\gateway-proxy.inc"
    }

    $gatewayCompose = Join-Path $Root "services\gateway\docker-compose.yml"
    if (-not (Test-Path -LiteralPath $gatewayCompose)) {
        throw "Missing $gatewayCompose. Copy scripts\setup-public-https.ps1 into the Aetheris project that already runs aetheris-gateway, then run it from that folder."
    }
    Write-Ok "Nginx HTTPS config ready for $CertName"
}

function Ensure-SelfSignedCertInVolume {
    param([string]$Root, [string]$PublicIP)

    Write-Step "Installing self-signed certificate for $PublicIP"
    $live = "/etc/letsencrypt/live/$PublicIP"
    $shell = "apk add --no-cache openssl >/dev/null && mkdir -p $live && openssl req -x509 -nodes -newkey rsa:2048 -days 825 -keyout $live/privkey.pem -out $live/fullchain.pem -subj /CN=$PublicIP -addext subjectAltName=IP:$PublicIP && ls -la $live"
    Invoke-Docker -ArgumentList @(
        "run", "--rm",
        "-v", "aetheris-gateway_certbot_etc:/etc/letsencrypt",
        "nginx:1.27-alpine",
        "sh", "-c", $shell
    ) -FailureMessage "Could not create self-signed certificate"
    Write-Ok "Self-signed cert present in certbot_etc volume (browsers will show a warning)"
}

function Issue-LetsEncryptCert {
    param(
        [string]$Root,
        [string]$PublicIP,
        [string]$Domain,
        [string]$Email,
        [switch]$Staging
    )
    if (-not $Email) {
        throw "Provide -Email for Let's Encrypt, or use -SelfSigned."
    }

    Write-Step "Starting ACME HTTP bootstrap on port 80"
    $compose = Get-ComposeArgs -Root $Root

    # Free port 80 if gateway already binds it. Ignore a missing container.
    [void](Invoke-DockerExit -ArgumentList ($compose + @("stop", "gateway")))

    Invoke-Docker -ArgumentList ($compose + @("--profile", "acme-bootstrap", "up", "-d", "acme-bootstrap")) `
        -FailureMessage "Could not start acme-bootstrap (is TCP 80 free, and is router forwarding 80 to $LanIP?)"

    try {
        $certName = if ($Domain) { $Domain } else { $PublicIP }
        $extra = @()
        if ($Staging) {
            $extra += "--staging"
            $certName = "$certName-staging"
            Write-WarnMsg "Requesting STAGING certificate (not trusted by browsers)."
        } elseif ($Domain) {
            Write-Host "Requesting Let's Encrypt certificate for $Domain ..."
        } else {
            Write-Host "Requesting Let's Encrypt short-lived IP certificate for $PublicIP ..."
        }

        $certArgs = $compose + @(
            "--profile", "certbot",
            "run", "--rm", "certbot",
            "certonly",
            "--webroot",
            "--webroot-path", "/var/www/certbot",
            "--cert-name", $certName,
            "--email", $Email,
            "--agree-tos",
            "--non-interactive"
        )
        if ($Domain) {
            $certArgs += @("-d", $Domain)
        } else {
            $certArgs += @("--preferred-profile", "shortlived", "--ip-address", $PublicIP)
        }
        $certArgs += $extra

        Invoke-Docker -ArgumentList $certArgs -FailureMessage "Let's Encrypt certificate request failed"
        Write-Ok "Certificate issued for $certName"
    }
    finally {
        Write-Host "Stopping ACME bootstrap..."
        [void](Invoke-DockerExit -ArgumentList ($compose + @("--profile", "acme-bootstrap", "rm", "-sf", "acme-bootstrap")))
    }
}

function Start-PublicGateway {
    param([string]$Root, [switch]$ForceRecreate)
    Write-Step "Starting aetheris-gateway with public HTTPS (80/443)"
    $compose = Get-ComposeArgs -Root $Root
    # Do not pass --remove-orphans: this script sets COMPOSE_IGNORE_ORPHANS=true,
    # and Compose rejects that combination.
    $up = $compose + @("up", "-d")
    if ($ForceRecreate) { $up += "--force-recreate" }
    # Build only if image missing — keep this fast for re-runs.
    $imageRc = Invoke-DockerExit -ArgumentList @("image", "inspect", "aetheris-gateway")
    if ($imageRc -ne 0) {
        Invoke-Docker -ArgumentList ($compose + @("build", "gateway")) -FailureMessage "Gateway image build failed"
    }
    Invoke-Docker -ArgumentList $up -FailureMessage "Gateway public HTTPS up failed"
    Write-Ok "Gateway is up"
}

function Update-AppBaseUrlHints {
    param([string]$Root, [string]$PublicHost)
    $url = "https://$PublicHost"
    foreach ($rel in @(
            ".env",
            "services\forensic\.env",
            "services\vuln\.env",
            "services\mobile-extract\.env"
        )) {
        $path = Join-Path $Root $rel
        if (-not (Test-Path -LiteralPath $path)) { continue }
        $raw = [System.IO.File]::ReadAllText($path)
        if ($raw -match '(?m)^APP_BASE_URL=') {
            $raw = [regex]::Replace($raw, '(?m)^APP_BASE_URL=.*$', "APP_BASE_URL=$url")
        } else {
            $raw = $raw.TrimEnd() + "`r`nAPP_BASE_URL=$url`r`n"
        }
        [System.IO.File]::WriteAllText($path, $raw)
        Write-Ok "Set APP_BASE_URL=$url in $rel"
    }
    Write-WarnMsg "Recreate forensic/vuln/mobile API containers so they pick up APP_BASE_URL (compose up -d --force-recreate api)."
}

# -------------------- main --------------------
Assert-Administrator

if (-not $ProjectRoot) {
    $ProjectRoot = (Resolve-Path (Join-Path $PSScriptRoot "..")).Path
}
Set-Location $ProjectRoot

$Domain = $Domain.Trim().TrimEnd('.')
$certName = if ($Domain) { $Domain } else { $PublicIP }
if ($SelfSigned -and $Domain) {
    throw "Chrome error NET::ERR_CERT_AUTHORITY_INVALID is the self-signed certificate. Re-run without -SelfSigned, with -Domain $Domain and -Email."
}

Write-Step "Public HTTPS setup"
Write-Host "Project:   $ProjectRoot"
Write-Host "Public URL: https://$certName"
Write-Host "Public IP: $PublicIP"
Write-Host "LAN IP:    $LanIP"
Write-Host "Router must forward TCP 80 and 443 from $PublicIP -> ${LanIP}:80 / ${LanIP}:443"
Write-Host ""

if (-not $SkipLanCheck) {
    Assert-LanIp -Expected $LanIP
}

Ensure-PublicHttpsFiles -Root $ProjectRoot -PublicIP $PublicIP -CertName $certName

if (-not $SkipFirewall) {
    Write-Step "Windows Firewall"
    Ensure-FirewallRule -Name "Aetheris HTTPS 443" -Port 443
    Ensure-FirewallRule -Name "Aetheris HTTP 80 (ACME + redirect)" -Port 80
}

if (-not $SkipCert) {
    if ($SelfSigned) {
        Ensure-SelfSignedCertInVolume -Root $ProjectRoot -PublicIP $PublicIP
    } else {
        Issue-LetsEncryptCert -Root $ProjectRoot -PublicIP $PublicIP -Domain $Domain -Email $Email -Staging:$Staging
        if ($Staging) {
            Write-WarnMsg "Staging succeeded. Re-run without -Staging for a trusted certificate."
            return
        }
    }
}

Update-AppBaseUrlHints -Root $ProjectRoot -PublicHost $certName
Start-PublicGateway -Root $ProjectRoot -ForceRecreate:$ForceRecreate

Write-Step "Verify"
Write-Host "Local (LAN):     http://${LanIP}:3001"
Write-Host "Public HTTPS:    https://$certName"
Write-Host "Health (vuln):   https://$certName/health"
Write-Host "Laptop agent:    CENTRAL_API_URL=https://$certName"
Write-Host ""
Write-Host "Quick checks:"
Write-Host "  curl.exe -k https://127.0.0.1/health"
Write-Host "  curl.exe -k https://$PublicIP/health"
Write-Host "  Test-NetConnection $PublicIP -Port 443"
Write-Host ""
Write-Ok "Done. If HTTPS works on LAN but not from outside, fix router port-forward / ISP CGNAT."
