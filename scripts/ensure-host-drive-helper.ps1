# Ensure the host drive helper is running on port 9876 (Windows examiner workstation).
param(
    [switch]$ForceRestart
)

$ErrorActionPreference = "Stop"
$Port = if ($env:HOST_DRIVE_HELPER_PORT) { [int]$env:HOST_DRIVE_HELPER_PORT } else { 9876 }
$BindHost = if ($env:HOST_DRIVE_HELPER_BIND_HOST) { [string]$env:HOST_DRIVE_HELPER_BIND_HOST } else { "+" }
$root = Split-Path -Parent (Split-Path -Parent $MyInvocation.MyCommand.Path)
$kit = Join-Path $root "scripts\ensure-examiner-kit.ps1"
$networkConfig = Join-Path $root "scripts\configure-host-drive-helper-network.ps1"
$helper = Join-Path $root "scripts\host-drive-helper.ps1"
$agent = Join-Path $root "scripts\hostdrive-agent.ps1"
$ExpectedHelperVersion = "5.36"

function Test-IsAdministrator {
    try {
        $identity = [Security.Principal.WindowsIdentity]::GetCurrent()
        $principal = New-Object Security.Principal.WindowsPrincipal($identity)
        return $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
    } catch { return $false }
}

function Test-WildcardUrlAcl {
    param([int]$ListenPort)
    try {
        $url = "http://+:$ListenPort/"
        $out = (& netsh http show urlacl url=$url 2>$null | Out-String)
        if ($out -notmatch [regex]::Escape($url)) { return $false }
        # A copied/extracted project can inherit a URL ACL created for a different
        # Windows account.  Merely seeing the URL in netsh is not sufficient: the
        # current examiner account must be allowed to bind it.
        $identity = [Security.Principal.WindowsIdentity]::GetCurrent().Name
        if (-not $identity) { return $false }
        return ($out -match [regex]::Escape($identity))
    } catch { return $false }
}

function Test-DockerFirewallRule {
    try {
        $rule = Get-NetFirewallRule -DisplayName "Aetheris HostDrive Helper (Docker)" -ErrorAction SilentlyContinue
        return ($null -ne $rule -and $rule.Enabled -eq "True")
    } catch { return $false }
}

function Ensure-DockerReachableBinding {
    if ($BindHost -ne "+") { return }
    if ((Test-WildcardUrlAcl -ListenPort $Port) -and (Test-DockerFirewallRule)) { return }
    if (-not (Test-Path -LiteralPath $networkConfig)) {
        Write-Warning "Missing $networkConfig; falling back to localhost-only helper."
        $script:BindHost = "127.0.0.1"
        return
    }
    Write-Host "Configuring HostDrive helper so Docker can reach Windows USB tools..." -ForegroundColor Cyan
    try {
        if (Test-IsAdministrator) {
            & powershell.exe -NoProfile -ExecutionPolicy Bypass -File $networkConfig -Port $Port
            if ($LASTEXITCODE -ne 0) { throw "network configuration exit $LASTEXITCODE" }
        } else {
            $args = '-NoProfile -ExecutionPolicy Bypass -File "' + $networkConfig + '" -Port ' + $Port
            $proc = Start-Process powershell.exe -Verb RunAs -ArgumentList $args -Wait -PassThru
            if ($proc.ExitCode -ne 0) { throw "elevated network configuration exit $($proc.ExitCode)" }
        }
    } catch {
        Write-Warning "Docker bridge setup was not completed: $($_.Exception.Message)"
    }
    if (-not (Test-WildcardUrlAcl -ListenPort $Port)) {
        Write-Warning "Wildcard URL ACL is unavailable. Starting localhost-only helper; browser detection can work, but Docker-side acquisition may remain unavailable."
        $script:BindHost = "127.0.0.1"
    }
}

function Ensure-AdbPortableBestEffort {
    $adb = Join-Path $root "tools\platform-tools\adb.exe"
    if (Test-Path -LiteralPath $adb) { return }
    try {
        Write-Host "Installing portable Android platform-tools (adb)..." -ForegroundColor Cyan
        $tools = Join-Path $root "tools"
        New-Item -ItemType Directory -Force -Path $tools | Out-Null
        $zip = Join-Path $env:TEMP "aetheris-platform-tools.zip"
        $extract = Join-Path $env:TEMP "aetheris-platform-tools-extract"
        Invoke-WebRequest -Uri "https://dl.google.com/android/repository/platform-tools-latest-windows.zip" -OutFile $zip -UseBasicParsing
        if (Test-Path -LiteralPath $extract) { Remove-Item -LiteralPath $extract -Recurse -Force -ErrorAction SilentlyContinue }
        Expand-Archive -LiteralPath $zip -DestinationPath $extract -Force
        $src = Join-Path $extract "platform-tools"
        $dst = Join-Path $tools "platform-tools"
        if (Test-Path -LiteralPath $dst) { Remove-Item -LiteralPath $dst -Recurse -Force -ErrorAction SilentlyContinue }
        Move-Item -LiteralPath $src -Destination $dst
        Remove-Item -LiteralPath $zip -Force -ErrorAction SilentlyContinue
        if (Test-Path -LiteralPath $adb) { Write-Host "adb ready: $adb" -ForegroundColor Green }
    } catch {
        Write-Warning "Could not install adb automatically: $($_.Exception.Message). MTP detection will still be available."
    }
}

# Mobile helper startup must not fail just because optional iOS tooling could not be installed.
if (Test-Path -LiteralPath $kit) {
    try {
        Write-Host "Ensuring examiner kit (portable adb + iOS usbmux python)..."
        & powershell.exe -NoProfile -ExecutionPolicy Bypass -File $kit
        if ($LASTEXITCODE -ne 0) { throw "examiner kit exit $LASTEXITCODE" }
    } catch {
        Write-Warning "Full examiner kit setup was incomplete: $($_.Exception.Message)"
    }
}
Ensure-AdbPortableBestEffort
Ensure-DockerReachableBinding

function Register-HostDriveProtocol {
    # HKCU only — no elevation. Stops Chromium "scheme does not have a registered
    # handler" if anything still opens aetheris-hostdrive:refresh.
    try {
        $base = "HKCU:\Software\Classes\aetheris-hostdrive"
        New-Item -Path $base -Force | Out-Null
        Set-ItemProperty -Path $base -Name "(default)" -Value "URL:Aetheris HostDrive Agent"
        Set-ItemProperty -Path $base -Name "URL Protocol" -Value ""
        $cmdKey = Join-Path $base "shell\open\command"
        New-Item -Path $cmdKey -Force | Out-Null
        $target = if (Test-Path -LiteralPath $agent) { $agent } else { $helper }
        $cmd = 'powershell.exe -NoProfile -WindowStyle Hidden -ExecutionPolicy Bypass -File "' + $target + '"'
        if ($target -eq $agent) { $cmd += ' -RefreshNow -Once' }
        Set-ItemProperty -Path $cmdKey -Name "(default)" -Value $cmd
    }
    catch { }
}
Register-HostDriveProtocol
$healthUrl = "http://127.0.0.1:$Port/health"
$stateDir = Join-Path $env:LOCALAPPDATA "Aetheris"
$pidFile = Join-Path $stateDir "host-drive-helper.pid"

function Get-HelperHealth {
    try { return Invoke-RestMethod -Uri $healthUrl -TimeoutSec 2 } catch { return $null }
}

function Test-HelperHealth {
    $health = Get-HelperHealth
    return ($null -ne $health -and [bool]$health.ok)
}

function Get-LocalJobScriptVersion {
    $job = Join-Path $root "scripts\refresh-drive-mounts-job.ps1"
    try {
        if (-not (Test-Path -LiteralPath $job)) { return $null }
        foreach ($line in @(Get-Content -LiteralPath $job -TotalCount 40 -ErrorAction Stop)) {
            if (("$line") -match 'AETHERIS_JOB_VERSION:\s*([0-9][0-9A-Za-z.\-]*)') { return $Matches[1] }
        }
        return "legacy"
    }
    catch { return $null }
}

# A helper is a long-lived process bound to one port. If a helper from ANOTHER
# checkout (e.g. F:\rag_new2 vs E:\aetheris_project) or one started before a
# hotfix is still running, it will keep launching its own (old) job script and
# no amount of extracting new files fixes anything. Detect that and restart.
function Test-HelperStale {
    param($Health)
    if ($null -eq $Health) { return $false }
    $rootFull = [System.IO.Path]::GetFullPath($root).TrimEnd('\')
    $helperRoot = [string]$Health.root
    if (-not $helperRoot) {
        Write-Host "Running helper predates v4.6 (no root/version on /health) - restarting it."
        return $true
    }
    try { $helperRoot = [System.IO.Path]::GetFullPath($helperRoot).TrimEnd('\') } catch { }
    if (-not $helperRoot.Equals($rootFull, [StringComparison]::OrdinalIgnoreCase)) {
        Write-Host "Running helper belongs to a different checkout ($helperRoot); this one is $rootFull - restarting it."
        return $true
    }
    $loadedVersion = [string]$Health.helper_version
    if (-not $loadedVersion -or $loadedVersion -ne $ExpectedHelperVersion) {
        Write-Host "Running helper version '$loadedVersion' is stale; expected v$ExpectedHelperVersion - restarting it."
        return $true
    }
    $loadedBind = [string]$Health.bind_host
    if ($BindHost -eq "+" -and $loadedBind -ne "+") {
        Write-Host "Running helper is localhost-only (bind_host=$loadedBind); Docker USB bridge requires wildcard binding - restarting it."
        return $true
    }
    $local = Get-LocalJobScriptVersion
    $loaded = [string]$Health.job_script_version
    if ($local -and $loaded -and $local -ne $loaded) {
        Write-Host "Running helper reports job script v$loaded but disk has v$local - restarting it."
        return $true
    }
    return $false
}

$currentHealth = Get-HelperHealth
if ((-not $ForceRestart) -and $currentHealth -and [bool]$currentHealth.ok) {
    if (-not (Test-HelperStale -Health $currentHealth)) {
        Write-Host ("Host drive helper already running on {0} (root={1}, job v{2}, pid {3})" -f $healthUrl, $currentHealth.root, $currentHealth.job_script_version, $currentHealth.helper_pid)
        exit 0
    }
    $ForceRestart = $true
}

if ($ForceRestart) {
    Write-Host "Force-restarting host drive helper on port $Port..."
}

# Health timed out or failed — helper may be wedged on a long /acquisition/run.
# Free port 9876 so a responsive helper can start; leave child python/idevice
# processes alone so an in-flight backup can keep writing evidence.
function Stop-HelperOnPort {
    param([int]$ListenPort)
    try {
        $owners = @(Get-NetTCPConnection -LocalPort $ListenPort -State Listen -ErrorAction SilentlyContinue |
            Select-Object -ExpandProperty OwningProcess -Unique)
        foreach ($opid in $owners) {
            if (-not $opid) { continue }
            $p = Get-Process -Id $opid -ErrorAction SilentlyContinue
            if ($p -and ($p.ProcessName -match '^(powershell|pwsh)$')) {
                Write-Host "Stopping unresponsive helper pid $opid on port $ListenPort..."
                Stop-Process -Id $opid -Force -ErrorAction SilentlyContinue
            }
        }
    } catch {}
    # HttpListener often shows as PID 4 (System). Also stop any helper script process.
    try {
        Get-CimInstance Win32_Process -Filter "Name='powershell.exe' OR Name='pwsh.exe'" -ErrorAction SilentlyContinue |
            Where-Object {
                $_.CommandLine -and
                $_.CommandLine -match 'host-drive-helper\.ps1' -and
                $_.CommandLine -notmatch 'ensure-host-drive-helper'
            } |
            ForEach-Object {
                Write-Host "Stopping helper script pid $($_.ProcessId)..."
                Stop-Process -Id $_.ProcessId -Force -ErrorAction SilentlyContinue
            }
    } catch {}
}

if (Test-Path $pidFile) {
    try {
        $oldPid = [int](Get-Content $pidFile -ErrorAction Stop | Select-Object -First 1)
        $proc = Get-Process -Id $oldPid -ErrorAction SilentlyContinue
        if ($proc -and $proc.ProcessName -match '^(powershell|pwsh)$') {
            Write-Host "Stopping stale helper process $oldPid..."
            Stop-Process -Id $oldPid -Force -ErrorAction SilentlyContinue
            Start-Sleep -Seconds 1
        }
    } catch {
        # ignore stale pid file
    }
}
Stop-HelperOnPort -ListenPort $Port
Start-Sleep -Seconds 1

New-Item -ItemType Directory -Force -Path $stateDir | Out-Null

$stdoutLog = Join-Path $stateDir "host-drive-helper.out.log"
$stderrLog = Join-Path $stateDir "host-drive-helper.err.log"

function Show-HelperStartupLog {
    Write-Host ""
    Write-Host "HostDrive helper startup diagnostics:" -ForegroundColor Yellow
    foreach ($logPath in @($stderrLog, $stdoutLog)) {
        if (Test-Path -LiteralPath $logPath) {
            Write-Host ("--- {0} ---" -f $logPath) -ForegroundColor DarkGray
            try { Get-Content -LiteralPath $logPath -Tail 40 -ErrorAction SilentlyContinue | ForEach-Object { Write-Host $_ } } catch { }
        }
    }
}

function Start-HelperBackground {
    param([string]$RequestedBindHost)

    Remove-Item -LiteralPath $stdoutLog -Force -ErrorAction SilentlyContinue
    Remove-Item -LiteralPath $stderrLog -Force -ErrorAction SilentlyContinue

    # IMPORTANT: Start-Process flattens ArgumentList to one command line. The -File
    # path therefore has to be explicitly quoted. Without this, extracting Aetheris
    # into a directory containing spaces makes powershell.exe exit immediately and
    # the UI reports port 9876 offline.
    $args = @(
        "-NoProfile",
        "-ExecutionPolicy", "Bypass",
        "-File", ('"' + $helper + '"'),
        "-Port", ([string]$Port),
        "-BindHost", ('"' + $RequestedBindHost + '"')
    )

    $psExe = Join-Path $env:SystemRoot "System32\WindowsPowerShell\v1.0\powershell.exe"
    if (-not (Test-Path -LiteralPath $psExe)) { $psExe = "powershell.exe" }
    return Start-Process -FilePath $psExe `
        -ArgumentList $args `
        -PassThru `
        -WindowStyle Hidden `
        -RedirectStandardOutput $stdoutLog `
        -RedirectStandardError $stderrLog
}

function Wait-HelperOnline {
    param($Process, [string]$RequestedBindHost, [int]$Seconds = 20)
    for ($i = 0; $i -lt $Seconds; $i++) {
        Start-Sleep -Seconds 1
        if (Test-HelperHealth) {
            Write-Host "Host drive helper is online: $healthUrl (bind=$RequestedBindHost, pid $($Process.Id))" -ForegroundColor Green
            return $true
        }
        try { $Process.Refresh() } catch { }
        if ($Process.HasExited) {
            Write-Host "Helper process exited early (code $($Process.ExitCode))." -ForegroundColor Red
            Show-HelperStartupLog
            return $false
        }
    }
    Write-Host "Helper did not respond within $Seconds seconds (pid $($Process.Id))." -ForegroundColor Red
    Show-HelperStartupLog
    return $false
}

Write-Host "Starting host drive helper on port $Port in background..."
$proc = Start-HelperBackground -RequestedBindHost $BindHost
Set-Content -Path $pidFile -Value $proc.Id -Encoding ascii

if (Wait-HelperOnline -Process $proc -RequestedBindHost $BindHost) {
    exit 0
}

# If wildcard binding was blocked, keep the browser-side USB path functional by
# falling back to loopback. The repair command can later restore the Docker bridge.
if ($BindHost -eq "+") {
    Write-Host "Retrying HostDrive helper on 127.0.0.1 so local browser USB detection remains available..." -ForegroundColor Yellow
    try { Stop-Process -Id $proc.Id -Force -ErrorAction SilentlyContinue } catch { }
    Start-Sleep -Milliseconds 500
    $fallbackBind = "127.0.0.1"
    $proc2 = Start-HelperBackground -RequestedBindHost $fallbackBind
    Set-Content -Path $pidFile -Value $proc2.Id -Encoding ascii
    if (Wait-HelperOnline -Process $proc2 -RequestedBindHost $fallbackBind -Seconds 12) {
        Write-Host "WARNING: helper is localhost-only. Device detection in the browser works; run Repair-Mobile-USB.cmd once as Administrator to restore Docker acquisition access." -ForegroundColor Yellow
        exit 0
    }
}

Write-Host "For auto-start at logon run: scripts\install-host-drive-helper-task.ps1"
exit 1
