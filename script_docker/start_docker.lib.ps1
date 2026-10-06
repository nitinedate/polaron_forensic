# Windows PowerShell 5.1-compatible helpers. Dot-sourceable for offline checks.

function Write-Step([string]$Message) {
    Write-Host ""
    Write-Host "==> $Message" -ForegroundColor Cyan
}

function Invoke-Docker {
    param([string]$Title, [Parameter(Mandatory = $true)][string[]]$DockerArgs)
    if ($Title) { Write-Host $Title }
    & docker @DockerArgs
    if ($LASTEXITCODE -ne 0) { throw "Docker action '$Title' failed (exit $LASTEXITCODE)." }
}

function Get-DockerJson {
    param([string[]]$DockerArgs)
    $raw = & docker @DockerArgs
    if ($LASTEXITCODE -ne 0) { throw "Could not inspect the Docker configuration." }
    return (($raw -join "`n") | ConvertFrom-Json)
}

function Get-StackComposeArgs {
    param([string]$Root, [string]$Name)
    return @("compose", "--project-directory", $Root, "--project-name", "aetheris-$Name",
        "-f", "services/$Name/docker-compose.yml")
}

function Write-NewDeploymentFile {
    param([string]$Path, [string]$Text)
    # Exclusive creation preserves a configuration written by another launch.
    $stream = $null
    try {
        $stream = [System.IO.File]::Open($Path, [System.IO.FileMode]::CreateNew,
            [System.IO.FileAccess]::Write, [System.IO.FileShare]::None)
    } catch [System.IO.IOException] {
        if (Test-Path -LiteralPath $Path -PathType Leaf) { return }
        throw
    }
    try {
        $bytes = [System.Text.UTF8Encoding]::new($false).GetBytes($Text)
        $stream.Write($bytes, 0, $bytes.Length)
    } finally { $stream.Dispose() }
}

function New-DeploymentSecret {
    $bytes = New-Object byte[] 32
    $random = [System.Security.Cryptography.RandomNumberGenerator]::Create()
    try { $random.GetBytes($bytes) } finally { $random.Dispose() }
    return [System.BitConverter]::ToString($bytes).Replace('-', '').ToLowerInvariant()
}

function Initialize-DeploymentFiles {
    param([string]$Root, [ValidateSet('local', 'nitin', 'prod')][string]$Profile)
    $manifestPath = Join-Path $Root 'script_docker/start_docker.required-files.json'
    if (-not (Test-Path -LiteralPath $manifestPath -PathType Leaf)) {
        throw "Missing $manifestPath. Extract the complete startup update into the project root."
    }
    $required = Get-Content -LiteralPath $manifestPath -Raw | ConvertFrom-Json
    $files = @($required.common)
    if ($Profile -ne 'local') { $files += @($required.public) }
    $missing = @($files | Where-Object {
        -not (Test-Path -LiteralPath (Join-Path $Root $_) -PathType Leaf)
    })
    if ($missing.Count) {
        throw "Required deployment files are missing: $($missing -join ', '). Restore them from the complete project or startup update."
    }
    $envPath = Join-Path $Root '.env'
    if (-not (Test-Path -LiteralPath $envPath)) {
        $text = [System.IO.File]::ReadAllText((Join-Path $Root '.env.example'))
        $text = [regex]::Replace($text, '(?m)^JWT_SECRET=[^\r\n]*', ('JWT_SECRET=' + (New-DeploymentSecret)))
        $text = [regex]::Replace($text, '(?m)^CLIENT_TOKEN_SECRET=[^\r\n]*', ('CLIENT_TOKEN_SECRET=' + (New-DeploymentSecret)))
        Write-NewDeploymentFile -Path $envPath -Text $text
        Write-Host 'Created root .env from .env.example with fresh signing secrets.' -ForegroundColor Green
    }
    if (-not (Test-Path -LiteralPath $envPath -PathType Leaf) -or
        -not [System.IO.File]::ReadAllText($envPath).Trim()) {
        throw "The existing $envPath is empty or is not a file. Restore your configuration or copy .env.example; existing files are never overwritten."
    }
    $settingsPath = Join-Path $Root 'script_docker/start_docker.settings.json'
    if (-not (Test-Path -LiteralPath $settingsPath)) {
        $settingsText = [System.IO.File]::ReadAllText((Join-Path $Root 'script_docker/start_docker.settings.example.json'))
        Write-NewDeploymentFile -Path $settingsPath -Text $settingsText
        Write-Host 'Created script_docker/start_docker.settings.json from the supplied profile template.' -ForegroundColor Green
    }
    # Validate JSON here even for prepare-only, before any Docker operation.
    $settings = Get-Content -LiteralPath $settingsPath -Raw | ConvertFrom-Json
    foreach ($name in @('local', 'nitin', 'prod')) {
        if (-not $settings.$name) { throw "Deployment settings are missing the '$name' profile in $settingsPath." }
    }
}

function Assert-DeploymentComposePaths {
    param([string]$Root, $Config, [switch]$ValidateOnly)
    $runtimeTargets = @('/app/data', '/app/data/uploads', '/scratch', '/data',
        '/root/.ollama', '/root/.cache/huggingface', '/evidence')
    $generatedNginx = [System.IO.Path]::GetFullPath((Join-Path $Root 'deployment/windows-ip-https/nginx.gateway.https.conf'))
    foreach ($row in @($Config.services.PSObject.Properties)) {
        $service = $row.Value
        if ($service.build) {
            $context = [string]$service.build.context
            if (-not (Test-Path -LiteralPath $context -PathType Container)) { throw "Missing build context for $($row.Name): $context" }
            $dockerfile = if ($service.build.dockerfile) { [string]$service.build.dockerfile } else { 'Dockerfile' }
            if (-not (Test-Path -LiteralPath (Join-Path $context $dockerfile) -PathType Leaf)) {
                throw "Missing Dockerfile for $($row.Name): $context/$dockerfile"
            }
        }
        foreach ($mount in @($service.volumes)) {
            if ($mount.type -ne 'bind') { continue }
            $source = [string]$mount.source
            if (Test-Path -LiteralPath $source) {
                if ($runtimeTargets -contains [string]$mount.target -and
                    -not (Test-Path -LiteralPath $source -PathType Container)) {
                    throw "Expected a runtime directory for $($row.Name), but found a file: $source"
                }
                if ([System.IO.Path]::GetFullPath($source) -eq $generatedNginx -and
                    -not (Test-Path -LiteralPath $source -PathType Leaf)) {
                    throw "The generated HTTPS configuration path is a directory, not a file: $source"
                }
                continue
            }
            # HTTPS configuration is generated after the matching certificates exist.
            if ([System.IO.Path]::GetFullPath($source) -eq $generatedNginx) { continue }
            if ($runtimeTargets -contains [string]$mount.target) {
                if (-not $ValidateOnly) {
                    New-Item -ItemType Directory -Path $source -Force | Out-Null
                }
            } else {
                throw "Missing bind-mounted deployment file/directory for $($row.Name): $source (container path $($mount.target)). Restore the complete project."
            }
        }
    }
}

function Get-DeploymentSettings {
    param([string]$Root, [string]$Profile, [string]$PublicIP, [string]$Domain, [string]$AcmeEmail)
    $path = Join-Path $Root "script_docker\start_docker.settings.json"
    $source = if (Test-Path -LiteralPath $path) { $path } else {
        Join-Path $Root "script_docker\start_docker.settings.example.json"
    }
    $all = Get-Content -LiteralPath $source -Raw | ConvertFrom-Json
    $selected = $all.$Profile
    if (-not $selected) { throw "Deployment settings are missing the '$Profile' profile." }
    $ip = if ($PublicIP) { $PublicIP } else { [string]$selected.publicIp }
    $dns = if ($Domain) { $Domain } else { [string]$selected.domain }
    $email = if ($AcmeEmail) { $AcmeEmail } elseif ($env:CERTBOT_EMAIL) {
        $env:CERTBOT_EMAIL
    } else { [string]$selected.acmeEmail }
    if ($Profile -eq "prod") {
        if ($Domain) { throw "The prod launcher uses only an IP address. Use nitin for domain HTTPS." }
        $dns = ""
    }
    if ($Profile -ne "local") {
        # HTTP-01 needs a public IPv4 address, not a LAN/loopback address.
        $parsed = $null
        if ($ip -notmatch '^\d{1,3}(\.\d{1,3}){3}$' -or
            -not [System.Net.IPAddress]::TryParse($ip, [ref]$parsed)) {
            throw "Set a valid static public IPv4 address in $path or pass -PublicIP."
        }
        $octets = $parsed.GetAddressBytes()
        if ($octets[0] -eq 0 -or $octets[0] -eq 10 -or $octets[0] -eq 127 -or
            $octets[0] -ge 224 -or ($octets[0] -eq 169 -and $octets[1] -eq 254) -or
            ($octets[0] -eq 172 -and $octets[1] -ge 16 -and $octets[1] -le 31) -or
            ($octets[0] -eq 192 -and $octets[1] -eq 168) -or
            ($octets[0] -eq 100 -and $octets[1] -ge 64 -and $octets[1] -le 127)) {
            throw "HTTPS IP issuance needs your static public IPv4 address, not $ip."
        }
        $ip = $parsed.ToString()
        if ($Profile -eq "nitin") {
            $dns = $dns.Trim().ToLowerInvariant()
            if ($dns.Length -gt 253 -or $dns -notmatch '^(?=.{1,253}$)([a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}$') {
                throw "Set a valid DNS hostname for the nitin profile."
            }
        }
    }
    return [pscustomobject]@{ PublicIP = $ip; Domain = $dns; AcmeEmail = $email;
        Path = $path; All = $all }
}

function Save-DeploymentSettings {
    param($Settings, [string]$Profile)
    $row = $Settings.All.$Profile
    $row.publicIp = $Settings.PublicIP
    $row.domain = $Settings.Domain
    $row.acmeEmail = $Settings.AcmeEmail
    $text = $Settings.All | ConvertTo-Json -Depth 8
    [System.IO.File]::WriteAllText($Settings.Path, $text, [System.Text.UTF8Encoding]::new($false))
}

function Get-AppBuildArgs {
    param([string]$BuildId, [switch]$RefreshDependencies)
    if (-not $BuildId) { throw "Application build ID is required." }
    $buildOptions = @("build", "--build-arg", "AETHERIS_APP_BUILD_ID=$BuildId")
    if ($RefreshDependencies) { $buildOptions += @("--pull", "--no-cache") }
    return $buildOptions
}

function Get-PublicNginxConfig {
    param([string]$PublicIP, [string]$Domain)
    $ipCert = "aetheris-ip-$PublicIP"
    $blocks = @()
    $identities = @([pscustomobject]@{ Identity = "$PublicIP _"; Cert = $ipCert; Default = $true })
    if ($Domain) {
        $identities += [pscustomobject]@{ Identity = $Domain; Cert = "aetheris-domain-$Domain"; Default = $false }
    }
    foreach ($row in $identities) {
        $listen = if ($row.Default) { "listen 443 ssl default_server;" } else { "listen 443 ssl;" }
        $listen6 = if ($row.Default) { "listen [::]:443 ssl default_server;" } else { "listen [::]:443 ssl;" }
        $blocks += @"
server {
    $listen
    $listen6
    server_name $($row.Identity);
    ssl_certificate /etc/letsencrypt/live/$($row.Cert)/fullchain.pem;
    ssl_certificate_key /etc/letsencrypt/live/$($row.Cert)/privkey.pem;
    ssl_protocols TLSv1.2 TLSv1.3;
    ssl_session_cache shared:SSL:10m;
    ssl_session_timeout 1d;
    root /usr/share/nginx/html;
    index index.html;
    server_tokens off;
    client_max_body_size 0;
    include /etc/nginx/conf.d/gateway-https-locations.inc;
}
"@
    }
    $canonical = if ($Domain) { $Domain } else { $PublicIP }
    return @"
# Generated by script_docker/start_docker.ps1. Certificate renewal reloads nginx.
resolver 127.0.0.11 valid=10s ipv6=off;
map `$http_x_aetheris_service `$hdr_upstream {
    default http://host.docker.internal:8083;
    forensic http://host.docker.internal:8083;
    mobile-android http://host.docker.internal:8081;
    android http://host.docker.internal:8081;
    mobile-ios http://host.docker.internal:8084;
    ios http://host.docker.internal:8084;
    mobile-extract http://host.docker.internal:8081;
    mobile http://host.docker.internal:8081;
    vuln http://host.docker.internal:8082;
}
server {
    listen 80 default_server;
    listen [::]:80 default_server;
    server_name $PublicIP $Domain _;
    server_tokens off;
    location ^~ /.well-known/acme-challenge/ {
        root /var/www/certbot;
        default_type text/plain;
        try_files `$uri =404;
    }
    location = /gateway-health { return 200 "ok\n"; }
    location / { return 308 https://$canonical`$request_uri; }
}
$($blocks -join "`n")
"@
}

function Assert-PublicPortOwners {
    param([int[]]$Ports = @(80, 443))
    # Never stop IIS/Caddy/another Compose project to take its ports.
    $ids = @(& docker ps -q)
    if ($LASTEXITCODE -ne 0) { throw "Could not inspect Docker port owners." }
    if ($ids.Count -gt 0) {
        foreach ($id in $ids) {
            $items = @(Get-DockerJson -DockerArgs @("inspect", $id))
            $item = $items[0]
            $project = [string]$item.Config.Labels.'com.docker.compose.project'
            $service = [string]$item.Config.Labels.'com.docker.compose.service'
            foreach ($prop in @($item.HostConfig.PortBindings.PSObject.Properties)) {
                foreach ($bind in @($prop.Value)) {
                    if ($Ports -contains [int]$bind.HostPort -and
                        ($project -ne "aetheris-gateway" -or $service -notin @("gateway", "acme-bootstrap"))) {
                        throw "TCP $($bind.HostPort) is reserved by $($item.Name). Stop or reconfigure that owner first."
                    }
                }
            }
        }
    }
    foreach ($port in $Ports) {
        foreach ($listener in @(Get-NetTCPConnection -LocalPort $port -State Listen -ErrorAction SilentlyContinue)) {
            $proc = Get-Process -Id $listener.OwningProcess -ErrorAction SilentlyContinue
            if ($proc -and $proc.ProcessName -notmatch '^(docker|dockerd|vpnkit|wsl|wslservice|wslrelay|com\.docker)') {
                throw "TCP $port is held by $($proc.ProcessName) (PID $($proc.Id)). Stop or reconfigure it first."
            }
        }
    }
}

function Enable-PublicFirewall {
    $principal = New-Object Security.Principal.WindowsPrincipal([Security.Principal.WindowsIdentity]::GetCurrent())
    if (-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
        Write-Host "Run as Administrator to create inbound TCP 80/443 rules, or create those rules before starting." -ForegroundColor Yellow
        return
    }
    foreach ($port in @(80, 443)) {
        $name = "Aetheris HTTPS TCP $port"
        $existing = Get-NetFirewallRule -DisplayName $name -ErrorAction SilentlyContinue
        if ($existing) { $existing | Remove-NetFirewallRule | Out-Null }
        New-NetFirewallRule -DisplayName $name -Direction Inbound -Action Allow -Protocol TCP -LocalPort $port -Profile Any | Out-Null
    }
}

function Invoke-CertificateTool {
    param([string[]]$ComposeArgs, [string[]]$ToolArgs)
    $raw = & docker @ComposeArgs run --rm --no-deps --pull missing --entrypoint python certbot /tools/public_https.py @ToolArgs
    if ($LASTEXITCODE -ne 0) { throw "Certificate identity/trust check failed." }
    return (($raw -join "`n") | ConvertFrom-Json)
}

function Get-CertbotIssueArgs {
    param([string]$Identity, [string]$CertName, [string]$Email, [switch]$IsIP)
    $issueOptions = @("certonly", "--non-interactive", "--agree-tos", "--email", $Email,
        "--server", "https://acme-v02.api.letsencrypt.org/directory",
        "--webroot", "--webroot-path", "/var/www/certbot", "--preferred-challenges", "http",
        "--cert-name", $CertName, "--keep-until-expiring")
    if ($IsIP) { $issueOptions += @("--required-profile", "shortlived", "--ip-address", $Identity) }
    else { $issueOptions += @("-d", $Identity) }
    return $issueOptions
}

function Ensure-PublicCertificate {
    param([string[]]$ComposeArgs, [string]$Identity, [string]$CertName, [string]$Email, [switch]$IsIP)
    $check = Invoke-CertificateTool -ComposeArgs $ComposeArgs -ToolArgs @("inspect", "--name", $CertName, "--identity", $Identity)
    if ($check.managed) {
        # Certbot decides whether renewal is due (including ACME Renewal Information).
        Invoke-Docker -Title "Check renewal for $Identity" -DockerArgs ($ComposeArgs + @(
            "run", "--rm", "--no-deps", "--pull", "missing", "certbot", "renew",
            "--cert-name", $CertName, "--non-interactive", "--no-random-sleep-on-renew"))
    } else {
        $issue = Get-CertbotIssueArgs -Identity $Identity -CertName $CertName -Email $Email -IsIP:$IsIP
        Invoke-Docker -Title "Issue trusted HTTPS certificate for $Identity" -DockerArgs (
            $ComposeArgs + @("run", "--rm", "--no-deps", "--pull", "missing", "certbot") + $issue)
    }
    $check = Invoke-CertificateTool -ComposeArgs $ComposeArgs -ToolArgs @("inspect", "--name", $CertName, "--identity", $Identity)
    if (-not $check.valid) { throw "Certificate for $Identity is invalid: $($check.reason)." }
    Write-Host "Certificate ready for $Identity (expires $($check.expires_utc))."
}

function Test-AcmeRoute {
    param([string]$Token)
    try {
        $response = Invoke-WebRequest -UseBasicParsing -Uri "http://127.0.0.1/.well-known/acme-challenge/$Token" -TimeoutSec 10
        return ($response.StatusCode -eq 200 -and $response.Content.Trim() -eq $Token)
    } catch { return $false }
}

function Get-StackContainerReport {
    $failed = @()
    $pending = 0
    $running = 0
    $missing = @()
    $oneShots = @("ollama-init", "configure-openvas", "pg-gvm-migrator", "gpg-data", "postgres-ensure", "certbot", "acme-bootstrap")
    foreach ($project in @("aetheris-common", "aetheris-forensic", "aetheris-mobile-android", "aetheris-mobile-ios", "aetheris-vuln", "aetheris-gateway")) {
        $ids = @(& docker ps -aq --filter "label=com.docker.compose.project=$project")
        if ($LASTEXITCODE -ne 0) { throw "Could not inspect containers for $project." }
        if (-not $ids.Count) { $missing += $project; continue }
        foreach ($id in $ids) {
            $items = @(Get-DockerJson -DockerArgs @("inspect", $id))
            $item = $items[0]
            $status = [string]$item.State.Status
            $health = if ($item.State.Health) { [string]$item.State.Health.Status } else { "none" }
            $service = [string]$item.Config.Labels.'com.docker.compose.service'
            if ($status -eq "running" -and $health -in @("none", "healthy")) { $running++; continue }
            if ($status -eq "running" -and $health -eq "starting") { $pending++; continue }
            if ($service -in $oneShots -and $status -eq "exited" -and $item.State.ExitCode -eq 0) { continue }
            $failed += "$($item.Name) status=$status health=$health exit=$($item.State.ExitCode)"
        }
    }
    return [pscustomobject]@{ Running = $running; Pending = $pending; Failed = @($failed); Missing = @($missing) }
}


function Assert-PublicGatewayBindings {
    param([string[]]$ComposeArgs)
    $gateway = Get-DockerJson -DockerArgs ($ComposeArgs + @("ps", "--format", "json", "gateway"))
    $id = [string]$gateway.ID
    if (-not $id) { throw "HTTPS gateway is not running; TCP 443 is not ready." }
    $items = @(Get-DockerJson -DockerArgs @("inspect", $id))
    $container = $items[0]
    if (-not $container.State.Running) { throw "HTTPS gateway container is stopped." }
    foreach ($port in @(80, 443)) {
        $bindings = @($container.NetworkSettings.Ports."$port/tcp")
        $public = @($bindings | Where-Object {
            [string]$_.HostPort -eq [string]$port -and [string]$_.HostIp -in @("0.0.0.0", "::")
        })
        if (-not $public.Count) { throw "Gateway TCP $port is not published on a public host interface. Check the public HTTPS Compose override." }
    }
}

function Start-PublicHttpsGateway {
    param([string[]]$ComposeArgs, [string]$PublicIP, [string]$Domain)
    # This also removes an owned bootstrap left by an earlier interrupted launch.
    # Compose scopes the removal to aetheris-gateway; other projects are untouched.
    Invoke-Docker -Title "Release owned HTTP certificate bootstrap" -DockerArgs (
        $ComposeArgs + @("--profile", "acme-bootstrap", "rm", "-sf", "acme-bootstrap"))
    Invoke-Docker -Title "Start HTTPS gateway on TCP 80/443 and automatic renewal" -DockerArgs (
        $ComposeArgs + @("up", "-d", "--no-build", "--pull", "missing", "--force-recreate", "--wait", "--wait-timeout", "180", "gateway", "certbot-renewer"))
    Assert-PublicGatewayBindings -ComposeArgs $ComposeArgs
    Invoke-Docker -Title "Verify running HTTPS nginx" -DockerArgs ($ComposeArgs + @("exec", "-T", "gateway", "nginx", "-t"))
    Invoke-CertificateTool -ComposeArgs $ComposeArgs -ToolArgs @("probe", "--identity", $PublicIP) | Out-Null
    if ($Domain) { Invoke-CertificateTool -ComposeArgs $ComposeArgs -ToolArgs @("probe", "--identity", $Domain) | Out-Null }
    Write-Host "HTTPS edge is listening with verified certificates on TCP 443. Product API readiness is checked next." -ForegroundColor Green
}
