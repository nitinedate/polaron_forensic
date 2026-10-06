param([string]$ProjectRoot = (Split-Path -Parent $PSScriptRoot))
$ErrorActionPreference = 'Stop'
. (Join-Path $ProjectRoot 'script_docker/start_docker.lib.ps1')
$script:checks = 0
function Assert-True([bool]$Value, [string]$Message) {
    if (-not $Value) { throw "FAIL: $Message" }
    $script:checks++
}
function Assert-Throws([scriptblock]$Body, [string]$Message) {
    $threw = $false
    try { & $Body | Out-Null } catch { $threw = $true }
    Assert-True $threw $Message
}
$tempRoot = Join-Path ([System.IO.Path]::GetTempPath()) ('aetheris-start-check-' + [guid]::NewGuid().ToString('N'))
New-Item -ItemType Directory (Join-Path $tempRoot 'script_docker') -Force | Out-Null
Copy-Item (Join-Path $ProjectRoot 'script_docker/start_docker.settings.example.json') (Join-Path $tempRoot 'script_docker/start_docker.settings.example.json')
try {
    $prod = Get-DeploymentSettings -Root $tempRoot -Profile prod -AcmeEmail admin@example.com
    Assert-True ($prod.Domain -eq '') 'Production has no DNS dependency'
    Assert-True ($prod.PublicIP -eq '122.179.141.248') 'Production defaults stay configurable'
    $prod.PublicIP = '8.8.4.4'
    Save-DeploymentSettings -Settings $prod -Profile prod
    $persisted = Get-DeploymentSettings -Root $tempRoot -Profile prod
    Assert-True ($persisted.PublicIP -eq '8.8.4.4' -and $persisted.AcmeEmail -eq 'admin@example.com') 'User settings persist across launches'
    $nitin = Get-DeploymentSettings -Root $tempRoot -Profile nitin
    Assert-True ($nitin.Domain -eq 'future-softtech.co.in') 'Nitin domain defaults retained'
    $custom = Get-DeploymentSettings -Root $tempRoot -Profile nitin -PublicIP 8.8.8.8 -Domain example.org
    Assert-True ($custom.Domain -eq 'example.org' -and $custom.PublicIP -eq '8.8.8.8') 'CLI host overrides work'
    foreach ($badIP in @('192.168.1.10','10.0.0.1','172.16.0.1','127.0.0.1','169.254.1.1','100.64.0.1','224.1.1.1','999.1.1.1','1.2.3.4;id')) {
        Assert-Throws { Get-DeploymentSettings -Root $tempRoot -Profile prod -PublicIP $badIP } "Reject private or malformed IP: $badIP"
    }
    Assert-Throws { Get-DeploymentSettings -Root $tempRoot -Profile prod -Domain example.org } 'Production rejects domain overrides'
    Assert-Throws { Get-DeploymentSettings -Root $tempRoot -Profile nitin -Domain 'a;return 200;' } 'Reject nginx domain injection'
    $normal = @(Get-AppBuildArgs -BuildId first)
    $next = @(Get-AppBuildArgs -BuildId second)
    Assert-True ($normal -notcontains '--no-cache' -and $normal -notcontains '--pull') 'Normal application builds retain dependencies'
    Assert-True ($normal[-1] -ne $next[-1]) 'Every launch can invalidate application compilation'
    $refresh = @(Get-AppBuildArgs -BuildId first -RefreshDependencies)
    Assert-True ($refresh -contains '--no-cache' -and $refresh -contains '--pull') 'Dependency refresh is explicit'
    Assert-Throws { Get-AppBuildArgs -BuildId '' } 'Empty application build ID is rejected'
    $nginxProd = Get-PublicNginxConfig -PublicIP 8.8.8.8
    Assert-True ($nginxProd -match 'aetheris-ip-8.8.8.8/fullchain.pem' -and $nginxProd -notmatch 'aetheris-domain') 'IP configuration has no domain certificate'
    Assert-True ($nginxProd -match 'return 308 https://8.8.8.8\$request_uri') 'Production HTTP redirects to configured IP'
    Assert-True ($nginxProd -match 'location \^~ /\.well-known/acme-challenge/' -and $nginxProd -match 'listen 80 default_server' -and $nginxProd -match 'listen 443 ssl default_server') 'HTTP-01 remains available on public ports'
    $nginxNitin = Get-PublicNginxConfig -PublicIP 8.8.8.8 -Domain example.org
    Assert-True ($nginxNitin -match 'aetheris-domain-example.org' -and $nginxNitin -match 'aetheris-ip-8.8.8.8') 'Domain and IP get separate TLS certificates'
    $ipIssue = @(Get-CertbotIssueArgs -Identity 8.8.8.8 -CertName aetheris-ip-8.8.8.8 -Email admin@example.com -IsIP)
    Assert-True ($ipIssue -contains '--ip-address' -and $ipIssue -contains 'shortlived' -and $ipIssue -notcontains '-d' -and $ipIssue -notcontains '--staging') 'IP issuance uses production shortlived ACME profile'
    $domainIssue = @(Get-CertbotIssueArgs -Identity example.org -CertName aetheris-domain-example.org -Email admin@example.com)
    Assert-True ($domainIssue -contains '-d' -and $domainIssue -notcontains '--ip-address') 'Domain issuance uses DNS identifier'

    $script:dockerCalls = New-Object System.Collections.Generic.List[object]
    function Invoke-Docker {
        param([string]$Title, [string[]]$DockerArgs)
        $script:dockerCalls.Add(@($DockerArgs))
    }
    $script:managed = $true
    function Invoke-CertificateTool {
        param([string[]]$ComposeArgs, [string[]]$ToolArgs)
        return [pscustomobject]@{ managed = $script:managed; valid = $true; expires_utc = 'test' }
    }
    Ensure-PublicCertificate -ComposeArgs @('compose') -Identity 8.8.8.8 -CertName aetheris-ip-8.8.8.8 -Email admin@example.com -IsIP
    Assert-True ($script:dockerCalls[0] -contains 'renew' -and $script:dockerCalls[0] -notcontains 'certonly') 'Existing certificates are renewed only when due'
    $script:managed = $false
    Ensure-PublicCertificate -ComposeArgs @('compose') -Identity 8.8.8.8 -CertName aetheris-ip-8.8.8.8 -Email admin@example.com -IsIP
    Assert-True ($script:dockerCalls[1] -contains 'certonly') 'Missing certificate lineage is acquired'
    function Get-NetTCPConnection { param($LocalPort,$State,$ErrorAction); return @() }
    function docker { $global:LASTEXITCODE = 0; return @('fake-container') }
    $script:owner = 'another-project'
    function Get-DockerJson {
        param([string[]]$DockerArgs)
        return [pscustomobject]@{ Name = '/test'; Config = [pscustomobject]@{ Labels = [pscustomobject]@{
            'com.docker.compose.project' = $script:owner; 'com.docker.compose.service' = 'gateway'
        }}; HostConfig = [pscustomobject]@{PortBindings = [pscustomobject]@{'80/tcp' = @([pscustomobject]@{HostPort = '80'})}} }
    }
    Assert-Throws { Assert-PublicPortOwners } 'Another Docker project owning TCP 80 blocks deployment'
    $script:owner = 'aetheris-gateway'
    Assert-PublicPortOwners
    Assert-True $true 'Own gateway can be upgraded without removing another project'
    function Get-NetTCPConnection { param($LocalPort,$State,$ErrorAction); return @([pscustomobject]@{OwningProcess=4242}) }
    function Get-Process { param($Id,$ErrorAction); return [pscustomobject]@{ProcessName='caddy';Id=4242} }
    Assert-Throws { Assert-PublicPortOwners } 'Caddy/IIS port conflicts are reported without termination'
    Write-Host "PASS: $script:checks Windows startup behavior checks (offline Docker mocks)."
} finally { Remove-Item -LiteralPath $tempRoot -Recurse -Force }
