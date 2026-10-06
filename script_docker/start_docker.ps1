# Windows PowerShell 5.1 entrypoint. Application always compiles; dependencies stay cached.
param(
    [Parameter(Mandatory = $true)][ValidateSet("local", "nitin", "prod")][string]$Profile,
    [Parameter(Position = 0)][ValidateSet("", "cache", "nocache", "no-cache", "refresh-dependencies")][string]$Mode = "",
    [string]$PublicIP = "",
    [string]$Domain = "",
    [string]$AcmeEmail = "",
    [switch]$RefreshDependencies,
    [switch]$NoCache,
    [switch]$AutoRecoverEngine,
    [switch]$PrepareOnly,
    [switch]$ValidateOnly
)
$ErrorActionPreference = "Stop"
$PSNativeCommandUseErrorActionPreference = $false
$root = Split-Path -Parent $PSScriptRoot
. (Join-Path $PSScriptRoot "start_docker.lib.ps1")
$savedBaseUrl = $env:APP_BASE_URL
$bootstrapStarted = $false
$renewerStopped = $false
$challengeToken = ""
$gatewayArgs = $null
Push-Location $root
try {
    if ($NoCache -or $Mode -in @("nocache", "no-cache", "refresh-dependencies")) { $RefreshDependencies = $true }
    Write-Step "Prepare required deployment files"
    Initialize-DeploymentFiles -Root $root -Profile $Profile
    if ($PrepareOnly) {
        Write-Host "Deployment files are ready. Existing .env and host settings were preserved." -ForegroundColor Green
        return
    }
    if (-not (Get-Command docker -ErrorAction SilentlyContinue)) { throw "Install/start Docker Desktop with Linux containers first." }
    if (-not $ValidateOnly) {
        $osType = & docker info --format '{{.OSType}}'
        if ($LASTEXITCODE -ne 0 -or "$osType".Trim() -ne "linux") { throw "Docker Desktop must be running in Linux container mode." }
    }
    $composeVersion = & docker compose version --short
    if ($LASTEXITCODE -ne 0 -or "$composeVersion" -notmatch 'v?(\d+\.\d+\.\d+)') { throw "Docker Compose v2 is required." }
    if ([version]$Matches[1] -lt [version]"2.24.4") { throw "Update Docker Desktop: Compose 2.24.4 or newer is required." }
    if (-not $ValidateOnly) {
        & docker buildx version | Out-Null
        if ($LASTEXITCODE -ne 0) { throw "Docker Buildx/BuildKit is required. Update Docker Desktop." }
    }
    $env:DOCKER_BUILDKIT = "1"
    $settings = Get-DeploymentSettings -Root $root -Profile $Profile -PublicIP $PublicIP -Domain $Domain -AcmeEmail $AcmeEmail
    $isPublic = $Profile -ne "local"
    if ($isPublic -and -not $ValidateOnly) {
        if (-not $settings.AcmeEmail) { $settings.AcmeEmail = Read-Host "Email for Let's Encrypt (saved for future launches)" }
        $parsedEmail = New-Object System.Net.Mail.MailAddress($settings.AcmeEmail)
        if ($parsedEmail.Address -ne $settings.AcmeEmail) { throw "Enter a plain valid email address for Let's Encrypt." }
        Save-DeploymentSettings -Settings $settings -Profile $Profile
        $identity = if ($settings.Domain) { $settings.Domain } else { $settings.PublicIP }
        $env:APP_BASE_URL = "https://$identity"
        Assert-PublicPortOwners
        Write-Host "HTTPS host: $env:APP_BASE_URL (static IP $($settings.PublicIP))."
    } elseif ($isPublic) {
        $identity = if ($settings.Domain) { $settings.Domain } else { $settings.PublicIP }
        $env:APP_BASE_URL = "https://$identity"
    } else { $env:APP_BASE_URL = "http://localhost:3000" }
    $gatewayArgs = @(Get-StackComposeArgs -Root $root -Name "gateway")
    $gatewayArgs += @("-f", "deployment/windows-ip-https/docker-compose.gateway-local.yml")
    if ($isPublic) { $gatewayArgs += @("-f", "deployment/windows-ip-https/docker-compose.gateway-public-https.yml") }
    $forensicArgs = @(Get-StackComposeArgs -Root $root -Name "forensic")
    $androidArgs = @(Get-StackComposeArgs -Root $root -Name "mobile-android")
    $iosArgs = @(Get-StackComposeArgs -Root $root -Name "mobile-ios")
    $vulnArgs = @(Get-StackComposeArgs -Root $root -Name "vuln")
    $vulnArgs += @("--profile", "vuln-scanners", "--profile", "gvm")
    $commonArgs = @(Get-StackComposeArgs -Root $root -Name "common")
    Write-Step "Validate deployment configuration"
    foreach ($composeArgs in @($commonArgs, $forensicArgs, $androidArgs, $iosArgs, $vulnArgs, $gatewayArgs)) {
        Invoke-Docker -Title "Compose configuration" -DockerArgs ($composeArgs + @("config", "--quiet"))
        $resolved = Get-DockerJson -DockerArgs ($composeArgs + @("config", "--format", "json"))
        Assert-DeploymentComposePaths -Root $root -Config $resolved -ValidateOnly:$ValidateOnly
    }
    if ($ValidateOnly) {
        Write-Host "Configuration and required files passed. No images were built and no containers were started." -ForegroundColor Green
        return
    }
    $buildId = [guid]::NewGuid().ToString("N")
    $buildArgs = @(Get-AppBuildArgs -BuildId $buildId -RefreshDependencies:$RefreshDependencies)
    Write-Host "Application build: $buildId"
    if ($RefreshDependencies) { Write-Host "Explicit dependency refresh: rebuild dependencies and check base-image updates." -ForegroundColor Yellow }
    else { Write-Host "Dependency cache enabled. Application compilation runs every launch." -ForegroundColor Green }
    Write-Step "Compile the shared backend once"
    $coreConfig = Get-DockerJson -DockerArgs ($forensicArgs + @("config", "--format", "json"))
    $coreImage = [string]$coreConfig.services.api.image
    if (-not $coreImage) { throw "Forensic API must have an explicit image name." }
    # Reuse only compatible backend builds; service-specific behavior is runtime config.
    $apiConfigs = @()
    foreach ($targetArgs in @($androidArgs, $iosArgs, $vulnArgs)) {
        $config = Get-DockerJson -DockerArgs ($targetArgs + @("config", "--format", "json"))
        $baseBuild = $coreConfig.services.api.build
        $targetBuild = $config.services.api.build
        $baseTorch = if ($baseBuild.args.TORCH_INDEX_URL) { $baseBuild.args.TORCH_INDEX_URL } else { "https://download.pytorch.org/whl/cu130" }
        $targetTorch = if ($targetBuild.args.TORCH_INDEX_URL) { $targetBuild.args.TORCH_INDEX_URL } else { "https://download.pytorch.org/whl/cu130" }
        if ($baseBuild.context -ne $targetBuild.context -or $baseBuild.dockerfile -ne $targetBuild.dockerfile -or $baseTorch -ne $targetTorch) {
            throw "API images have different dependency settings; align TORCH_INDEX_URL before sharing the backend build."
        }
        $apiConfigs += $config
    }
    Invoke-Docker -Title "Backend application compile" -DockerArgs ($forensicArgs + $buildArgs + @("api"))
    foreach ($config in $apiConfigs) {
        $targetImage = [string]$config.services.api.image
        if (-not $targetImage) { throw "Each API must have an explicit image name." }
        if ($targetImage -ne $coreImage) { Invoke-Docker -Title "Reuse backend for $targetImage" -DockerArgs @("tag", $coreImage, $targetImage) }
    }
    Write-Step "Compile scanner worker and all three React applications"
    Invoke-Docker -Title "Scanner worker" -DockerArgs ($vulnArgs + $buildArgs + @("worker-nessus"))
    Invoke-Docker -Title "Android frontend" -DockerArgs ($androidArgs + $buildArgs + @("frontend"))
    Invoke-Docker -Title "iOS frontend" -DockerArgs ($iosArgs + $buildArgs + @("frontend"))
    Invoke-Docker -Title "Unified gateway frontend" -DockerArgs ($gatewayArgs + $buildArgs + @("gateway"))
    if ($isPublic) {
        Write-Step "Trusted IP/domain HTTPS certificates"
        Enable-PublicFirewall
        # A Windows checkout may convert shell scripts to CRLF. This bind-mounted
        # script executes in Linux, so normalize it before the sidecar starts.
        $renewalPath = Join-Path $PSScriptRoot "renew-certificates.sh"
        $renewalText = [System.IO.File]::ReadAllText($renewalPath).Replace("`r`n", "`n")
        [System.IO.File]::WriteAllText($renewalPath, $renewalText, [System.Text.UTF8Encoding]::new($false))
        $certbotImage = "certbot/certbot:v5.8.0"
        $inspectPreference = $ErrorActionPreference
        $ErrorActionPreference = "Continue"
        & docker image inspect $certbotImage 1>$null 2>$null
        $imageMissing = $LASTEXITCODE -ne 0
        $ErrorActionPreference = $inspectPreference
        if ($imageMissing -or $RefreshDependencies) { Invoke-Docker -Title "Certificate client image" -DockerArgs @("pull", $certbotImage) }
        foreach ($volume in @("aetheris-gateway_certbot_etc", "aetheris-gateway_certbot_www")) {
            Invoke-Docker -Title "Persistent certificate volume" -DockerArgs @("volume", "create", $volume)
        }
        $renewerIds = @(& docker @gatewayArgs ps -q certbot-renewer)
        if ($LASTEXITCODE -ne 0) { throw "Could not inspect the certificate renewal service." }
        if ($renewerIds.Count) {
            Invoke-Docker -Title "Pause renewal during deployment" -DockerArgs ($gatewayArgs + @("stop", "-t", "30", "certbot-renewer"))
            $renewerStopped = $true
        }
        $challengeToken = [guid]::NewGuid().ToString("N")
        Invoke-CertificateTool -ComposeArgs $gatewayArgs -ToolArgs @("challenge", "--token", $challengeToken) | Out-Null
        if (-not (Test-AcmeRoute -Token $challengeToken)) {
            $runningGateway = @(& docker @gatewayArgs ps -q gateway)
            if ($runningGateway.Count -and (& docker port $runningGateway[0] 80/tcp) -match ':80$') {
                throw "The current gateway is not serving its ACME webroot. Restore the ACME location before requesting certificates."
            }
            Assert-PublicPortOwners
            Invoke-Docker -Title "Start HTTP-only certificate bootstrap on TCP 80" -DockerArgs (
                $gatewayArgs + @("--profile", "acme-bootstrap", "up", "-d", "--no-build", "--pull", "missing", "--force-recreate", "acme-bootstrap"))
            $bootstrapStarted = $true
            $ready = $false
            for ($attempt = 0; $attempt -lt 10; $attempt++) {
                if (Test-AcmeRoute -Token $challengeToken) { $ready = $true; break }
                Start-Sleep -Seconds 2
            }
            if (-not $ready) { throw "Local HTTP-01 challenge route is unavailable on TCP 80." }
        }
        Write-Host "Local HTTP-01 route ready. Router/ISP must forward public TCP 80 and 443 to this PC."
        Ensure-PublicCertificate -ComposeArgs $gatewayArgs -Identity $settings.PublicIP -CertName "aetheris-ip-$($settings.PublicIP)" -Email $settings.AcmeEmail -IsIP
        if ($settings.Domain) {
            Ensure-PublicCertificate -ComposeArgs $gatewayArgs -Identity $settings.Domain -CertName "aetheris-domain-$($settings.Domain)" -Email $settings.AcmeEmail
        }
        $text = Get-PublicNginxConfig -PublicIP $settings.PublicIP -Domain $settings.Domain
        $configPath = Join-Path $root "deployment\windows-ip-https\nginx.gateway.https.conf"
        $candidatePath = Join-Path $root "deployment\windows-ip-https\nginx.gateway.candidate.conf"
        [System.IO.File]::WriteAllText($candidatePath, $text, [System.Text.UTF8Encoding]::new($false))
        $mountRoot = $root.Replace('\', '/')
        Invoke-Docker -Title "Validate nginx and certificate/key pair" -DockerArgs @("run", "--rm",
            "-v", "${mountRoot}/deployment/windows-ip-https/nginx.gateway.candidate.conf:/etc/nginx/conf.d/default.conf:ro",
            "-v", "${mountRoot}/deployment/windows-ip-https/gateway-https-locations.inc:/etc/nginx/conf.d/gateway-https-locations.inc:ro",
            "-v", "${mountRoot}/frontend/gateway-proxy.inc:/etc/nginx/conf.d/gateway-proxy.inc:ro",
            "-v", "aetheris-gateway_certbot_etc:/etc/letsencrypt:ro", "aetheris-gateway", "nginx", "-t")
        [System.IO.File]::WriteAllText($configPath, $text, [System.Text.UTF8Encoding]::new($false))
        Remove-Item -LiteralPath $candidatePath
    }
    Write-Step "Start all product stacks with freshly compiled images"
    $stackArgs = @("-NoProfile", "-ExecutionPolicy", "Bypass", "-File", (Join-Path $root "scripts\start-stack.ps1"),
        "-Service", "all", "-NoBuild", "-SkipGateway")
    if ($isPublic) { $stackArgs += "-LoopbackUi" }
    if ($AutoRecoverEngine) { $stackArgs += "-AutoRecoverEngine" }
    & powershell.exe @stackArgs
    if ($LASTEXITCODE -ne 0) { throw "Product-stack startup failed (exit $LASTEXITCODE)." }
    if ($bootstrapStarted) {
        Invoke-Docker -Title "Release HTTP bootstrap port" -DockerArgs ($gatewayArgs + @("--profile", "acme-bootstrap", "rm", "-sf", "acme-bootstrap"))
        $bootstrapStarted = $false
    }
    $gatewayServices = @("gateway")
    if ($isPublic) { $gatewayServices += "certbot-renewer" }
    Invoke-Docker -Title "Start gateway" -DockerArgs ($gatewayArgs + @("up", "-d", "--no-build", "--pull", "missing",
        "--force-recreate", "--wait", "--wait-timeout", "180") + $gatewayServices)
    $renewerStopped = $false
    Write-Step "Check container health and HTTPS trust"
    $report = Get-StackContainerReport
    if ($report.Failed.Count -or $report.Missing.Count -or $report.Pending) {
        $report.Failed | ForEach-Object { Write-Host $_ -ForegroundColor Red }
        throw "Container check: $($report.Failed.Count) failed, $($report.Pending) starting; missing: $($report.Missing -join ', ')."
    }
    if ($isPublic) {
        Invoke-Docker -Title "Running nginx configuration" -DockerArgs ($gatewayArgs + @("exec", "-T", "gateway", "nginx", "-t"))
        Invoke-CertificateTool -ComposeArgs $gatewayArgs -ToolArgs @("probe", "--identity", $settings.PublicIP) | Out-Null
        Invoke-CertificateTool -ComposeArgs $gatewayArgs -ToolArgs @("probe", "--identity", $settings.PublicIP, "--path", "/health") | Out-Null
        if ($settings.Domain) { Invoke-CertificateTool -ComposeArgs $gatewayArgs -ToolArgs @("probe", "--identity", $settings.Domain) | Out-Null }
        Write-Host "Ready: https://$($settings.PublicIP)/" -ForegroundColor Green
        if ($settings.Domain) { Write-Host "Ready: https://$($settings.Domain)/" -ForegroundColor Green }
        Write-Host "Automatic renewal checks run every 6 hours and reload nginx after successful renewal."
    } else {
        $response = Invoke-WebRequest -UseBasicParsing -Uri "http://127.0.0.1:3000/" -TimeoutSec 15
        if ($response.StatusCode -ne 200) { throw "Local gateway did not return HTTP 200." }
        Write-Host "Ready: http://localhost:3000/ (alias http://localhost:3001/)" -ForegroundColor Green
    }
    Write-Host "Android UI: http://localhost:3002/  iOS UI: http://localhost:3004/"
    Write-Host "$($report.Running) containers are running. Dependencies were reused unless explicitly refreshed."
} catch {
    Write-Host "START FAILED: $($_.Exception.Message)" -ForegroundColor Red
    if ($Profile -ne "local" -and -not $PrepareOnly -and -not $ValidateOnly) {
        Write-Host "For a certificate validation failure, check public TCP 80/443 forwarding and DNS (nitin)."
    }
    exit 1
} finally {
    if ($challengeToken -and $gatewayArgs) {
        try { Invoke-CertificateTool -ComposeArgs $gatewayArgs -ToolArgs @("challenge", "--token", $challengeToken, "--remove") | Out-Null } catch { }
    }
    if ($bootstrapStarted) { & docker @gatewayArgs --profile acme-bootstrap rm -sf acme-bootstrap 2>$null | Out-Null }
    if ($renewerStopped) { & docker @gatewayArgs start certbot-renewer 2>$null | Out-Null }
    $env:APP_BASE_URL = $savedBaseUrl
    Pop-Location
}
