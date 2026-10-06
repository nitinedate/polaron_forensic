param([string]$ProjectRoot = (Split-Path -Parent $PSScriptRoot))
$ErrorActionPreference = 'Stop'
. (Join-Path $ProjectRoot 'script_docker/start_docker.lib.ps1')
$script:checks = 0
function Assert-True([bool]$Value, [string]$Message) {
    if (-not $Value) { throw "FAIL: $Message" }
    $script:checks++
}
function Assert-Throws([scriptblock]$Body, [string]$Expected) {
    $message = ''
    try { & $Body | Out-Null } catch { $message = $_.Exception.Message }
    Assert-True ($message -like "*$Expected*") "Expected failure mentioning $Expected"
}
function Copy-Fixture([string]$Destination) {
    $manifest = Get-Content (Join-Path $ProjectRoot 'script_docker/start_docker.required-files.json') -Raw | ConvertFrom-Json
    foreach ($name in @($manifest.common) + @($manifest.public) + @('script_docker/start_docker.required-files.json')) {
        $path = Join-Path $Destination $name
        New-Item -ItemType Directory -Path (Split-Path -Parent $path) -Force | Out-Null
        Copy-Item -LiteralPath (Join-Path $ProjectRoot $name) -Destination $path
    }
}
$temp = Join-Path ([System.IO.Path]::GetTempPath()) ('aetheris-file-check-' + [guid]::NewGuid().ToString('N'))
try {
    foreach ($profile in @('local', 'nitin', 'prod')) {
        $fixture = Join-Path $temp $profile
        Copy-Fixture $fixture
        Initialize-DeploymentFiles -Root $fixture -Profile $profile
        $envPath = Join-Path $fixture '.env'
        $settingsPath = Join-Path $fixture 'script_docker/start_docker.settings.json'
        Assert-True (Test-Path $envPath -PathType Leaf) "$profile creates .env"
        Assert-True (Test-Path $settingsPath -PathType Leaf) "$profile creates host settings"
        $envText = [System.IO.File]::ReadAllText($envPath)
        Assert-True ($envText -match '(?m)^JWT_SECRET=[a-f0-9]{64}\r?$') "$profile generates a signing secret"
        Assert-True ($envText -match '(?m)^CLIENT_TOKEN_SECRET=[a-f0-9]{64}\r?$') "$profile generates a shared token secret"
        $initialEnv = (Get-FileHash $envPath).Hash
        $initialSettings = (Get-FileHash $settingsPath).Hash
        Initialize-DeploymentFiles -Root $fixture -Profile $profile
        Assert-True ((Get-FileHash $envPath).Hash -eq $initialEnv) "$profile preserves .env on relaunch"
        Assert-True ((Get-FileHash $settingsPath).Hash -eq $initialSettings) "$profile preserves settings on relaunch"
        $custom = "JWT_SECRET=existing-signing-value`nCLIENT_TOKEN_SECRET=existing-token`nAETHERIS_BACKUP_DIR=./existing-backup`n"
        [System.IO.File]::WriteAllText($envPath, $custom)
        Initialize-DeploymentFiles -Root $fixture -Profile $profile
        Assert-True ([System.IO.File]::ReadAllText($envPath) -eq $custom) "$profile preserves custom existing values exactly"
        Write-NewDeploymentFile -Path $envPath -Text 'replacement'
        Assert-True ([System.IO.File]::ReadAllText($envPath) -eq $custom) 'Exclusive creation preserves existing configuration'
    }
    $local = Join-Path $temp 'local'
    [System.IO.File]::WriteAllText((Join-Path $local '.env'), '')
    Assert-Throws { Initialize-DeploymentFiles -Root $local -Profile local } 'empty'
    Remove-Item (Join-Path $local '.env') -Force
    Remove-Item (Join-Path $local 'frontend/gateway-proxy.inc')
    Assert-Throws { Initialize-DeploymentFiles -Root $local -Profile local } 'frontend/gateway-proxy.inc'
    Assert-True (-not (Test-Path (Join-Path $local '.env'))) 'Missing source files fail before creating configuration'
    $runtimePath = Join-Path $temp 'runtime/backup'
    $config = [pscustomobject]@{services = [pscustomobject]@{api = [pscustomobject]@{
        volumes = @([pscustomobject]@{type='bind';source=$runtimePath;target='/app/data'})
    }}}
    Assert-DeploymentComposePaths -Root $local -Config $config -ValidateOnly
    Assert-True (-not (Test-Path $runtimePath)) 'Validation does not create runtime directories'
    Assert-DeploymentComposePaths -Root $local -Config $config
    Assert-True (Test-Path $runtimePath -PathType Container) 'Startup creates missing runtime directories'
    $config.services.api.volumes[0].target = '/etc/nginx/conf.d/default.conf'
    $config.services.api.volumes[0].source = Join-Path $temp 'missing.conf'
    Assert-Throws { Assert-DeploymentComposePaths -Root $local -Config $config } 'missing.conf'
    Assert-True (-not (Test-Path (Join-Path $temp 'missing.conf'))) 'Missing static files are not replaced with empty directories'
    $config.services.api.volumes[0].target = '/app/data'
    $config.services.api.volumes[0].source = Join-Path $temp 'wrong-type'
    Set-Content -LiteralPath $config.services.api.volumes[0].source -Value 'file'
    Assert-Throws { Assert-DeploymentComposePaths -Root $local -Config $config } 'Expected a runtime directory'
    Write-Host "PASS: $script:checks first-launch file checks (no Docker daemon required)."
} finally { if (Test-Path $temp) { Remove-Item -LiteralPath $temp -Recurse -Force } }
