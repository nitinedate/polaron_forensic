# V45.3b - Docker Desktop (WSL2) recovery for stuck containers.
#
# Symptom (production, during `docker compose up -d` recreate):
#   Error response from daemon: cannot stop container: <id>: tried to kill container,
#   but did not receive an exit event
#
# A process in the container is in an uninterruptible kernel state (Windows
# bind-mount file-sharing layer or an NVIDIA/CUDA call). No docker command can
# end it; only a docker-desktop VM restart can. This module:
#   1. stops workers with the configured grace period BEFORE recreate;
#   2. on the daemon error, tries `docker rm -f`; if that fails,
#   3. restarts the Docker Desktop engine (wsl --shutdown + relaunch) and waits
#      for `docker info` - gated by -AutoRecoverEngine.
#
# Windows PowerShell 5.1 rule (the V45.3a regression): when
# $ErrorActionPreference = "Stop" is in effect, redirecting a native command's
# stderr with 2>&1 turns EVERY stderr line into a terminating NativeCommandError.
# Docker Compose prints its progress ("Container x Running") on stderr, so the
# wrapper threw on the first healthy line. ALL native invocations in this file go
# through Invoke-NativeCapture, which lowers the preference to Continue for the
# duration of the call and converts ErrorRecords back into plain text.
# Dot-source from start-stack.ps1.

function Invoke-NativeCapture {
    <#
      Runs a native executable, merging stdout+stderr into plain text lines,
      without letting $ErrorActionPreference = "Stop" terminate on stderr.
      Returns @{ Lines = [string[]]; ExitCode = [int]; Text = [string] }.
    #>
    param(
        [Parameter(Mandatory = $true)][string]$Exe,
        [string[]]$Arguments = @()
    )
    # Resolve before lowering the preference: command-not-found must terminate
    # rather than inherit the exit code from an unrelated successful command.
    Get-Command -Name $Exe -ErrorAction Stop | Out-Null
    $previous = $ErrorActionPreference
    $ErrorActionPreference = "Continue"
    $raw = @()
    $code = 0
    try {
        $raw = @(& $Exe @Arguments 2>&1)
        $code = $LASTEXITCODE
    }
    catch {
        # Defensive: a host that still converts stderr into a terminating error.
        $raw += $_.Exception.Message
        # A launch/terminating error is a failure even if an earlier command
        # left LASTEXITCODE=0. Never report a failed invocation as successful.
        $code = -1
    }
    finally {
        $ErrorActionPreference = $previous
    }
    $lines = @()
    foreach ($item in $raw) {
        if ($null -eq $item) { continue }
        if ($item -is [System.Management.Automation.ErrorRecord]) {
            $lines += [string]$item.Exception.Message
        }
        else {
            $lines += [string]$item
        }
    }
    if ($null -eq $code) { $code = 0 }
    return @{ Lines = $lines; ExitCode = [int]$code; Text = ($lines -join "`n") }
}

function Test-DockerVolumeExists {
    param([string]$Docker, [string]$Name)
    $result = Invoke-NativeCapture -Exe $Docker -Arguments @('volume', 'inspect', $Name)
    if ($result.ExitCode -eq 0) { return $true }
    if ($result.Text -match '(?i)no such volume') { return $false }
    throw "Could not inspect Docker volume '$Name' (exit $($result.ExitCode)): $($result.Text)"
}

function Ensure-DockerVolume {
    param([string]$Docker, [string]$Name)
    if (Test-DockerVolumeExists -Docker $Docker -Name $Name) { return }
    $result = Invoke-NativeCapture -Exe $Docker -Arguments @('volume', 'create', $Name)
    if ($result.ExitCode -ne 0) {
        throw "Could not create Docker volume '$Name' (exit $($result.ExitCode)): $($result.Text)"
    }
}

function Test-StuckContainerError {
    param([string]$Text)
    if (-not $Text) { return $false }
    return ($Text -match "did not receive an exit event") -or
           ($Text -match "cannot stop container") -or
           ($Text -match "cannot kill container") -or
           ($Text -match "is not running or is not killable")
}

function Get-StuckContainerIds {
    param([string]$Text)
    $ids = @()
    foreach ($m in [regex]::Matches(($Text | Out-String), "container[: ]+([0-9a-f]{12,64})")) {
        $ids += $m.Groups[1].Value
    }
    return @($ids | Select-Object -Unique)
}

function Stop-AetherisWorkers {
    param(
        [string]$Docker,
        [string[]]$ComposeArgs,
        [string[]]$Services,
        [int]$GraceSec = 120
    )
    if (-not $Services.Count) { return $true }
    Write-Host "Stopping [$($Services -join ', ')] with ${GraceSec}s grace (Celery cold shutdown)..."
    $r = Invoke-NativeCapture -Exe $Docker -Arguments ($ComposeArgs + @("stop", "-t", "$GraceSec") + $Services)
    foreach ($line in $r.Lines) { Write-Host "  $line" }
    if ($r.ExitCode -eq 0) { return $true }
    return -not (Test-StuckContainerError $r.Text)
}

function Remove-StuckContainers {
    param([string]$Docker, [string[]]$Ids)
    $ok = $true
    foreach ($id in $Ids) {
        Write-Host "Force-removing stuck container $id ..." -ForegroundColor Yellow
        $r = Invoke-NativeCapture -Exe $Docker -Arguments @("rm", "-f", $id)
        foreach ($line in $r.Lines) { Write-Host "  $line" }
        if ($r.ExitCode -ne 0 -and (Test-StuckContainerError $r.Text)) { $ok = $false }
    }
    return $ok
}

function Wait-DockerEngine {
    param([string]$Docker, [int]$TimeoutSec = 420)
    $deadline = (Get-Date).AddSeconds($TimeoutSec)
    while ((Get-Date) -lt $deadline) {
        $r = Invoke-NativeCapture -Exe $Docker -Arguments @("info")
        if ($r.ExitCode -eq 0) { return $true }
        Start-Sleep -Seconds 5
    }
    return $false
}

function Restart-DockerDesktopEngine {
    param([string]$Docker)
    Write-Host ""
    Write-Host "Restarting the Docker Desktop engine to clear an unkillable container (docker-desktop VM restart)..." -ForegroundColor Yellow
    $candidates = @()
    if ($env:ProgramFiles) { $candidates += (Join-Path $env:ProgramFiles "Docker\Docker\Docker Desktop.exe") }
    if ($env:LOCALAPPDATA) { $candidates += (Join-Path $env:LOCALAPPDATA "Programs\Docker\Docker\Docker Desktop.exe") }
    $exe = $candidates | Where-Object { Test-Path -LiteralPath $_ } | Select-Object -First 1

    foreach ($name in @("Docker Desktop", "com.docker.backend")) {
        try { Get-Process -Name $name -ErrorAction SilentlyContinue | Stop-Process -Force -ErrorAction SilentlyContinue } catch {}
    }
    Start-Sleep -Seconds 3
    $wsl = Invoke-NativeCapture -Exe "wsl" -Arguments @("--shutdown")
    foreach ($line in $wsl.Lines) { if ($line) { Write-Host "  wsl: $line" } }
    Start-Sleep -Seconds 5
    if (-not $exe) {
        Write-Host "Docker Desktop.exe not found - start Docker Desktop manually, then re-run." -ForegroundColor Red
        return $false
    }
    Start-Process -FilePath $exe | Out-Null
    Write-Host "Waiting for the engine (up to 7 minutes)..."
    if (-not (Wait-DockerEngine -Docker $Docker -TimeoutSec 420)) {
        Write-Host "Docker engine did not come back." -ForegroundColor Red
        return $false
    }
    Write-Host "Docker engine is back." -ForegroundColor Green
    return $true
}

function Invoke-ComposeWithRecovery {
    <#
      Runs `docker <ComposeArgs> <ComposeCommand>`; on the stuck-container daemon
      error, performs rm -f -> engine restart (if -AutoRecoverEngine) -> one retry.
      Returns $true on success.
    #>
    param(
        [string]$Docker,
        [string[]]$ComposeArgs,
        [string[]]$ComposeCommand,
        [switch]$AutoRecoverEngine
    )
    $r = Invoke-NativeCapture -Exe $Docker -Arguments ($ComposeArgs + $ComposeCommand)
    foreach ($line in $r.Lines) { Write-Host $line }
    if ($r.ExitCode -eq 0) { return $true }
    if (-not (Test-StuckContainerError $r.Text)) { return $false }

    Write-Host ""
    Write-Host "Docker could not stop a container (process in uninterruptible I/O or CUDA call)." -ForegroundColor Yellow
    $ids = Get-StuckContainerIds $r.Text
    if ($ids.Count -and (Remove-StuckContainers -Docker $Docker -Ids $ids)) {
        Write-Host "Stuck container removed; retrying compose..."
    }
    elseif ($AutoRecoverEngine) {
        if (-not (Restart-DockerDesktopEngine -Docker $Docker)) { return $false }
    }
    else {
        Write-Host "Run again with -AutoRecoverEngine (or restart Docker Desktop manually: wsl --shutdown) and retry." -ForegroundColor Red
        return $false
    }
    $r = Invoke-NativeCapture -Exe $Docker -Arguments ($ComposeArgs + $ComposeCommand)
    foreach ($line in $r.Lines) { Write-Host $line }
    return ($r.ExitCode -eq 0)
}
