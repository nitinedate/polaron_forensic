[CmdletBinding()]
param(
    [string]$Root = "",
    [int]$InitialWaitMinutes = 10,
    [int]$RecoveryWaitMinutes = 20,
    [int]$FeedLoadWaitMinutes = 60,
    [switch]$RefreshFeedContainers
)

$ErrorActionPreference = 'Stop'
$ProgressPreference = 'SilentlyContinue'

function Read-EnvFile([string]$Path) {
    $map = @{}
    if (-not (Test-Path $Path)) { return $map }
    foreach ($line in [IO.File]::ReadAllLines($Path)) {
        if ($line -match '^\s*#') { continue }
        $i = $line.IndexOf('=')
        if ($i -lt 1) { continue }
        $k = $line.Substring(0, $i).Trim()
        $v = $line.Substring($i + 1).Trim()
        if (($v.StartsWith('"') -and $v.EndsWith('"')) -or ($v.StartsWith("'") -and $v.EndsWith("'"))) {
            if ($v.Length -ge 2) { $v = $v.Substring(1, $v.Length - 2) }
        }
        $map[$k] = $v
    }
    return $map
}

function Run-Docker([string[]]$ArgumentList, [switch]$AllowFailure) {
    $old = $ErrorActionPreference
    try {
        $ErrorActionPreference = 'Continue'
        $out = & docker.exe @ArgumentList 2>&1
        $code = $LASTEXITCODE
    }
    finally {
        $ErrorActionPreference = $old
    }
    $text = (@($out | ForEach-Object { $_.ToString() }) -join [Environment]::NewLine)
    if ((-not $AllowFailure) -and $code -ne 0) {
        throw "docker command failed ($code): docker $($ArgumentList -join ' ')`n$text"
    }
    return [pscustomobject]@{ ExitCode = $code; Text = $text }
}

function Compose([string[]]$ComposeArguments, [switch]$AllowFailure) {
    $all = @('compose', '--project-directory', $script:ProjectRoot, '-f', $script:ComposeFile) + $ComposeArguments
    return Run-Docker -ArgumentList $all -AllowFailure:$AllowFailure
}

function Get-ServiceContainerId([string]$Service) {
    $r = Compose -ComposeArguments @('ps', '-q', $Service) -AllowFailure
    if ($r.ExitCode -ne 0) { return $null }
    return (($r.Text -split '\s+') | Where-Object { $_ -match '^[a-f0-9]{8,}$' } | Select-Object -First 1)
}

function Wait-ContainerHealth([string]$Service, [int]$TimeoutSec = 300) {
    $deadline = (Get-Date).AddSeconds($TimeoutSec)
    while ((Get-Date) -lt $deadline) {
        $cid = Get-ServiceContainerId $Service
        if ($cid) {
            $r = Run-Docker -ArgumentList @('inspect', '-f', '{{if .State.Health}}{{.State.Health.Status}}{{else}}{{.State.Status}}{{end}}', $cid) -AllowFailure
            $state = (($r.Text -split '\s+') | Where-Object { $_ } | Select-Object -Last 1)
            if ($state -eq 'healthy' -or $state -eq 'running') { return $true }
        }
        Start-Sleep -Seconds 5
    }
    return $false
}

function Test-GreenboneReady {
    $cid = Get-ServiceContainerId 'scanner-agent'
    if (-not $cid) {
        return [pscustomobject]@{ Ready = $false; Text = 'scanner-agent container is not running' }
    }
    $r = Compose -ComposeArguments @('exec', '-T', 'scanner-agent', 'python', '/app/check_greenbone_ready.py') -AllowFailure
    return [pscustomobject]@{ Ready = ($r.ExitCode -eq 0); Text = $r.Text }
}

function Get-AdminUuid([string]$UserName) {
    $r = Compose -ComposeArguments @('exec', '-T', '-u', 'gvmd', 'gvmd', 'gvmd', '--get-users', '--verbose') -AllowFailure
    if ($r.ExitCode -ne 0) { return $null }
    foreach ($line in ($r.Text -split '\r?\n')) {
        $parts = @($line.Trim() -split '\s+')
        if ($parts.Count -ge 2 -and $parts[0].Equals($UserName, [StringComparison]::OrdinalIgnoreCase)) {
            if ($parts[1] -match '^[0-9a-fA-F-]{36}$') { return $parts[1] }
        }
    }
    return $null
}

function Ensure-FeedImportOwner([string]$UserName, [string]$Password) {
    if ([string]::IsNullOrWhiteSpace($UserName) -or $UserName -notmatch '^[A-Za-z0-9_.-]+$') {
        Write-Host "[WARN] Invalid Greenbone username [$UserName]; using built-in admin." -ForegroundColor Yellow
        $UserName = 'admin'
    }
    $uuid = Get-AdminUuid $UserName
    if (-not $uuid) {
        Write-Host "[WARN] Greenbone user '$UserName' was not found. Creating it." -ForegroundColor Yellow
        $create = Compose -ComposeArguments @('exec', '-T', '-u', 'gvmd', 'gvmd', 'gvmd', "--create-user=$UserName", "--password=$Password") -AllowFailure
        if ($create.Text) { Write-Host $create.Text }
        Start-Sleep -Seconds 3
        $uuid = Get-AdminUuid $UserName
    }
    if (-not $uuid) {
        throw "Could not determine the Greenbone user UUID for '$UserName'."
    }

    Write-Host "[INFO] Setting Feed Import Owner to $UserName ($uuid)."
    $set = Compose -ComposeArguments @('exec', '-T', '-u', 'gvmd', 'gvmd', 'gvmd', '--modify-setting', '78eceaec-3385-11ea-b237-28d24461215b', '--value', $uuid) -AllowFailure
    if ($set.ExitCode -ne 0) {
        throw "Failed to set the Feed Import Owner.`n$($set.Text)"
    }
    Write-Host '[OK] Feed Import Owner is configured.' -ForegroundColor Green
}

function Test-FeedVolume([string]$Service, [string]$FindExpression) {
    $r = Compose -ComposeArguments @('exec', '-T', $Service, 'sh', '-lc', $FindExpression) -AllowFailure
    if ($r.ExitCode -ne 0) { return $false }
    return -not [string]::IsNullOrWhiteSpace($r.Text)
}

function Get-GreenboneFeedState {
    $cid = Get-ServiceContainerId 'scanner-agent'
    if (-not $cid) {
        return [pscustomobject]@{ Ready = $false; ExitCode = 3; Text = 'scanner-agent container is not running' }
    }
    $r = Compose -ComposeArguments @('exec', '-T', 'scanner-agent', 'python', '/app/check_greenbone_feed_state.py') -AllowFailure
    return [pscustomobject]@{ Ready = ($r.ExitCode -eq 0); ExitCode = $r.ExitCode; Text = $r.Text }
}

function Wait-GreenboneFeedInventory([int]$Minutes) {
    # start-laptop used to pass 5 minutes. The first VT load is longer than that,
    # and ending the script closed the window before Full and fast could be built.
    $minimumMinutes = [Math]::Max(1, $Minutes)
    $ceilingMinutes = [Math]::Max($minimumMinutes, 180)
    $deadline = (Get-Date).AddMinutes($minimumMinutes)
    $hardStop = (Get-Date).AddMinutes($ceilingMinutes)
    $try = 0
    while ((Get-Date) -lt $hardStop) {
        $try++
        $state = Get-GreenboneFeedState
        if ($state.Ready) {
            Write-Host '[OK] OSPd OpenVAS NVT inventory is loaded.' -ForegroundColor Green
            if ($state.Text) { Write-Host $state.Text }
            return $true
        }
        $stillLoading = [string]$state.Text -match 'nvt_inventory_unavailable|nvt_inventory_loading|feed_syncing|still in progress|still loading|still synchronizing'
        if ((Get-Date) -ge $deadline) {
            if ($stillLoading) {
                $deadline = (Get-Date).AddMinutes(5)
                Write-Host ("[INFO] OSPd is still loading the VT feed (attempt {0}). This window stays open and will not shut down while loading (limit {1} minutes)." -f $try, $ceilingMinutes) -ForegroundColor Yellow
            } else {
                break
            }
        } elseif ($try -eq 1 -or ($try % 4) -eq 0) {
            Write-Host ("[INFO] OSPd is still loading the VT feed (attempt {0}). No restart will be performed while loading." -f $try) -ForegroundColor Yellow
        }
        if ($try -eq 1 -or ($try % 4) -eq 0) {
            if ($state.Text) { Write-Host $state.Text }
        }
        Start-Sleep -Seconds 15
    }
    return $false
}

function Rebuild-GvmdData {
    Write-Host '[INFO] Rebuilding gvmd feed-backed data objects (scan configs, port lists, report formats)...'
    $r = Compose -ComposeArguments @('exec', '-T', '-u', 'gvmd', 'gvmd', 'gvmd', '--rebuild-gvmd-data=all') -AllowFailure
    if ($r.Text) { Write-Host $r.Text }
    if ($r.ExitCode -ne 0) {
        throw "gvmd --rebuild-gvmd-data=all failed with exit code $($r.ExitCode)."
    }
    Write-Host '[OK] gvmd data-object rebuild was requested.' -ForegroundColor Green
}

function Wait-GreenboneReady([int]$Minutes, [string]$Phase) {
    $deadline = (Get-Date).AddMinutes([Math]::Max(1, $Minutes))
    $try = 0
    while ((Get-Date) -lt $deadline) {
        $try++
        $r = Test-GreenboneReady
        if ($r.Ready) {
            Write-Host "[OK] Greenbone READY during $Phase." -ForegroundColor Green
            Write-Host $r.Text
            return $true
        }
        if ($try -eq 1 -or ($try % 4) -eq 0) {
            Write-Host "[INFO] Greenbone still importing feed data ($Phase, attempt $try):"
            Write-Host $r.Text
        }
        Start-Sleep -Seconds 15
    }
    return $false
}

if ([string]::IsNullOrWhiteSpace($Root)) {
    $Root = (Resolve-Path -LiteralPath (Join-Path $PSScriptRoot '..')).Path
}
else {
    # Defensive normalization for native Windows CMD -> PowerShell argument
    # parsing.  A quoted path ending in a backslash can arrive as, for
    # example, D:\laptop-scanner".  Normalize it before Resolve-Path.
    $Root = $Root.Trim()
    while ($Root.Length -gt 0 -and ($Root.StartsWith('"') -or $Root.StartsWith("'"))) {
        $Root = $Root.Substring(1)
    }
    while ($Root.Length -gt 0 -and ($Root.EndsWith('"') -or $Root.EndsWith("'"))) {
        $Root = $Root.Substring(0, $Root.Length - 1)
    }
    while ($Root.Length -gt 3 -and ($Root.EndsWith('\') -or $Root.EndsWith('/'))) {
        $Root = $Root.Substring(0, $Root.Length - 1)
    }
    if (-not (Test-Path -LiteralPath $Root -PathType Container)) {
        throw "Scanner root does not exist or is not a directory: [$Root]"
    }
    $Root = (Resolve-Path -LiteralPath $Root).Path
}

$script:ProjectRoot = $Root
$script:ComposeFile = $null
foreach ($name in @('docker-compose.yml', 'docker-compose.yaml', 'compose.yml', 'compose.yaml')) {
    $candidate = Join-Path $Root $name
    if (Test-Path $candidate) { $script:ComposeFile = $candidate; break }
}
if (-not $script:ComposeFile) { throw "Docker Compose file not found under $Root" }

$envPath = Join-Path $Root '.env'
$envMap = Read-EnvFile $envPath
$gvmUser = [string]$envMap['GVM_USERNAME']
$gvmPassword = [string]$envMap['GVM_PASSWORD']
if ([string]::IsNullOrWhiteSpace($gvmUser)) { $gvmUser = 'admin' }
if ([string]::IsNullOrWhiteSpace($gvmPassword)) { $gvmPassword = 'admin' }

Write-Host '=============================================================================='
Write-Host 'Aetheris Greenbone feed / Full-and-fast repair v1.4.8'
Write-Host '=============================================================================='
Write-Host "Root=$Root"
Write-Host "Compose=$script:ComposeFile"
Write-Host "GVM user=$gvmUser"
Write-Host 'No Docker volumes are deleted by this repair.'
Write-Host ''

$info = Run-Docker -ArgumentList @('info') -AllowFailure
if ($info.ExitCode -ne 0) { throw 'Docker Desktop Linux engine is not ready.' }

Write-Host '==> Verifying Docker Compose argument forwarding'
$composeVersion = Run-Docker -ArgumentList @('compose', 'version') -AllowFailure
if ($composeVersion.ExitCode -ne 0) { throw "Docker Compose plugin is not available.`n$($composeVersion.Text)" }
$configServices = Compose -ComposeArguments @('config', '--services') -AllowFailure
if ($configServices.ExitCode -ne 0) { throw "Docker Compose could not load $script:ComposeFile.`n$($configServices.Text)" }
$serviceNames = @(($configServices.Text -split '\r?\n') | ForEach-Object { $_.Trim() } | Where-Object { $_ })
foreach ($requiredService in @('gvmd', 'ospd-openvas', 'scanner-agent', 'vulnerability-tests', 'data-objects')) {
    if ($serviceNames -notcontains $requiredService) { throw "Required Compose service is missing: $requiredService" }
}
Write-Host ('[OK] Docker command forwarding works. Compose services detected: {0}' -f $serviceNames.Count) -ForegroundColor Green

Write-Host '==> Ensuring Greenbone feed and manager services are running'
$upServices = @(
    'vulnerability-tests', 'notus-data', 'scap-data', 'cert-bund-data', 'dfn-cert-data',
    'data-objects', 'report-formats', 'redis-gvm', 'pg-gvm', 'ospd-openvas', 'gvmd', 'scanner-agent'
)
$up = Compose -ComposeArguments (@('up', '-d') + $upServices) -AllowFailure
if ($up.Text) { Write-Host $up.Text }
if ($up.ExitCode -ne 0) { throw 'Could not start required Greenbone services.' }

if (-not (Wait-ContainerHealth -Service 'ospd-openvas' -TimeoutSec 300)) {
    Write-Host '[WARN] ospd-openvas did not become healthy within 5 minutes.' -ForegroundColor Yellow
}
if (-not (Wait-ContainerHealth -Service 'gvmd' -TimeoutSec 300)) {
    throw 'gvmd did not become healthy within 5 minutes.'
}

Write-Host ''
Write-Host '==> Checking whether the feed files exist in Docker volumes'
$vtPresent = Test-FeedVolume -Service 'vulnerability-tests' -FindExpression "find /mnt -type f -name '*.nasl' -print -quit 2>/dev/null"
$dataPresent = Test-FeedVolume -Service 'data-objects' -FindExpression "find /mnt -type f -name '*.xml' -print -quit 2>/dev/null"
Write-Host ("VT files present: {0}" -f $vtPresent)
Write-Host ("GVMD data-object XML present: {0}" -f $dataPresent)

if ($RefreshFeedContainers -or (-not $vtPresent) -or (-not $dataPresent)) {
    Write-Host '[INFO] Refreshing feed data containers from the already-installed images.'
    $feedServices = @('vulnerability-tests', 'notus-data', 'scap-data', 'cert-bund-data', 'dfn-cert-data', 'data-objects', 'report-formats')
    $refresh = Compose -ComposeArguments (@('up', '-d', '--force-recreate') + $feedServices) -AllowFailure
    if ($refresh.Text) { Write-Host $refresh.Text }
    if ($refresh.ExitCode -ne 0) { throw 'Feed data container refresh failed.' }
    Start-Sleep -Seconds 10
}

Write-Host ''
Write-Host '==> Configuring Feed Import Owner'
Ensure-FeedImportOwner -UserName $gvmUser -Password $gvmPassword

Write-Host ''
Write-Host '==> Checking whether Greenbone is already fully ready'
$already = Test-GreenboneReady
if ($already.Ready) {
    Write-Host '[OK] Greenbone is already READY.' -ForegroundColor Green
    Write-Host $already.Text
    exit 0
}
if ($already.Text) { Write-Host $already.Text }

Write-Host ''
Write-Host ("==> Waiting up to {0} minute(s) for OSPd to finish initial VT/NVT loading" -f $FeedLoadWaitMinutes)
Write-Host '[INFO] Initial Greenbone feed loading can take several minutes to hours. The repair will NOT restart OSPd while it is loading.' -ForegroundColor Yellow
if (-not (Wait-GreenboneFeedInventory -Minutes $FeedLoadWaitMinutes)) {
    Write-Host ''
    Write-Host '[WAITING] OSPd OpenVAS is still loading the vulnerability-test feed.' -ForegroundColor Yellow
    Write-Host 'The laptop agent remains online but will not claim scan jobs until the NVT inventory is ready.'
    Write-Host 'Do NOT run docker compose down -v and do NOT repeatedly restart ospd-openvas.'
    Write-Host ''
    Write-Host 'Recent ospd-openvas logs:'
    $ospdLogs = Compose -ComposeArguments @('logs', '--tail', '120', 'ospd-openvas') -AllowFailure
    Write-Host $ospdLogs.Text
    exit 10
}

Write-Host ''
Write-Host '==> Rebuilding Greenbone manager data objects after NVT inventory became available'
Rebuild-GvmdData

Write-Host ''
Write-Host "==> Waiting up to $InitialWaitMinutes minute(s) for Full and fast"
if (Wait-GreenboneReady -Minutes $InitialWaitMinutes -Phase 'post-feed data rebuild') {
    Write-Host ''
    Write-Host 'REPAIR COMPLETE: Full and fast is available.' -ForegroundColor Green
    exit 0
}

Write-Host ''
Write-Host '[WARN] NVTs are loaded but Full and fast is still unavailable. Reloading gvmd data once; OSPd is not restarted.' -ForegroundColor Yellow
$restartGvmd = Compose -ComposeArguments @('restart', 'gvmd') -AllowFailure
if ($restartGvmd.Text) { Write-Host $restartGvmd.Text }
if (-not (Wait-ContainerHealth -Service 'gvmd' -TimeoutSec 600)) {
    throw 'gvmd did not become healthy after restart.'
}
Start-Sleep -Seconds 10
Ensure-FeedImportOwner -UserName $gvmUser -Password $gvmPassword
Rebuild-GvmdData

Write-Host ''
Write-Host "==> Waiting up to $RecoveryWaitMinutes minute(s) after gvmd reload"
if (Wait-GreenboneReady -Minutes $RecoveryWaitMinutes -Phase 'gvmd data reload') {
    Write-Host ''
    Write-Host 'REPAIR COMPLETE: Full and fast is available.' -ForegroundColor Green
    exit 0
}

Write-Host ''
Write-Host '[FAIL] NVT inventory is loaded, but Full and fast still was not imported.' -ForegroundColor Red
Write-Host 'Recent gvmd logs:'
$gvmdLogs = Compose -ComposeArguments @('logs', '--tail', '180', 'gvmd') -AllowFailure
Write-Host $gvmdLogs.Text
Write-Host ''
Write-Host 'Do NOT delete volumes. Check Feed Import Owner/data-object XML and PostgreSQL errors.'
exit 2

