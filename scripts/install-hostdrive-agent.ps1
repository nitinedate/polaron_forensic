# Install HostDrive Agent for the current examiner Windows session.
# The scheduled task is preferred, but Task Scheduler is intentionally NOT a
# hard dependency: Startup-folder + hidden-process fallbacks keep the app usable.

$ErrorActionPreference = "Stop"
$root = Split-Path -Parent (Split-Path -Parent $MyInvocation.MyCommand.Path)
$agent = Join-Path $root "scripts\hostdrive-agent.ps1"
$ensure = Join-Path $root "scripts\ensure-host-drive-helper.ps1"
$taskName = "AetherisHostDriveAgent"
$protocol = "aetheris-hostdrive"
$startupLauncher = Join-Path ([Environment]::GetFolderPath("Startup")) "AetherisHostDriveAgent.cmd"

if (-not (Test-Path -LiteralPath $agent)) {
    Write-Error "Missing HostDrive agent: $agent"
    exit 2
}
if (-not (Test-Path -LiteralPath $ensure)) {
    Write-Error "Missing HostDrive helper bootstrap: $ensure"
    exit 2
}

function Install-StartupFolderFallback {
    try {
        $startup = [Environment]::GetFolderPath("Startup")
        if (-not $startup) { throw "Windows Startup folder is unavailable." }
        New-Item -ItemType Directory -Force -Path $startup | Out-Null
        $launcher = Join-Path $startup "AetherisHostDriveAgent.cmd"
        $cmdBody = @(
            "@echo off",
            "powershell.exe -NoProfile -WindowStyle Hidden -ExecutionPolicy Bypass -File `"$agent`" -RefreshNow -WatchSeconds 30"
        ) -join "`r`n"
        Set-Content -LiteralPath $launcher -Value $cmdBody -Encoding ASCII
        Write-Host "Registered Startup folder fallback: $launcher"
        return $true
    }
    catch {
        Write-Warning ("Startup folder fallback failed: {0}" -f $_.Exception.Message)
        return $false
    }
}

function Remove-StartupFolderFallback {
    try {
        if (Test-Path -LiteralPath $startupLauncher) {
            Remove-Item -LiteralPath $startupLauncher -Force -ErrorAction SilentlyContinue
        }
    }
    catch { }
}

function Register-HostDriveProtocol {
    # HKCU protocol, so this does not require elevation. The React UI can invoke
    # aetheris-hostdrive:refresh if the localhost helper was stopped.
    $base = "HKCU:\Software\Classes\$protocol"
    New-Item -Path $base -Force | Out-Null
    Set-ItemProperty -Path $base -Name "(default)" -Value "URL:Aetheris HostDrive Agent"
    Set-ItemProperty -Path $base -Name "URL Protocol" -Value ""
    $cmdKey = Join-Path $base "shell\open\command"
    New-Item -Path $cmdKey -Force | Out-Null
    $cmd = 'powershell.exe -NoProfile -WindowStyle Hidden -ExecutionPolicy Bypass -File "' + $agent + '" -RefreshNow -Once'
    Set-ItemProperty -Path $cmdKey -Name "(default)" -Value $cmd
    Write-Host "Registered browser protocol: ${protocol}:refresh"
}

function Stop-OldAgentInstances {
    try { Stop-ScheduledTask -TaskName $taskName -ErrorAction SilentlyContinue } catch { }
    try {
        Get-CimInstance Win32_Process -ErrorAction SilentlyContinue |
            Where-Object {
                $_.Name -match '^powershell(\.exe)?$' -and
                $_.CommandLine -and
                $_.CommandLine.IndexOf('hostdrive-agent.ps1', [StringComparison]::OrdinalIgnoreCase) -ge 0 -and
                $_.ProcessId -ne $PID
            } |
            ForEach-Object {
                try { Stop-Process -Id $_.ProcessId -Force -ErrorAction SilentlyContinue } catch { }
            }
    }
    catch { }
}

function Start-HiddenAgentFallback {
    try {
        $already = @(Get-CimInstance Win32_Process -ErrorAction SilentlyContinue |
            Where-Object {
                $_.Name -match '^powershell(\.exe)?$' -and
                $_.CommandLine -and
                $_.CommandLine.IndexOf('hostdrive-agent.ps1', [StringComparison]::OrdinalIgnoreCase) -ge 0 -and
                $_.CommandLine.IndexOf('-WatchSeconds', [StringComparison]::OrdinalIgnoreCase) -ge 0
            })
        if ($already.Count -gt 0) {
            Write-Host "A HostDrive watcher process is already running."
            return $true
        }
        Start-Process powershell.exe -WindowStyle Hidden -ArgumentList @(
            "-NoProfile", "-ExecutionPolicy", "Bypass",
            "-File", ('"' + $agent + '"'), "-RefreshNow", "-WatchSeconds", "30"
        ) | Out-Null
        Start-Sleep -Milliseconds 500
        Write-Host "Started hidden HostDrive watcher fallback."
        return $true
    }
    catch {
        Write-Warning ("Hidden HostDrive watcher fallback failed: {0}" -f $_.Exception.Message)
        return $false
    }
}

function Try-RegisterScheduledWatcher {
    # Every Task Scheduler operation is inside this function/try. Some Windows
    # editions, endpoint-security policies, or user contexts reject one of the
    # ScheduledTasks cmdlets. That must never block the actual drive bridge.
    try {
        Import-Module ScheduledTasks -ErrorAction Stop
        $action = New-ScheduledTaskAction `
            -Execute "powershell.exe" `
            -Argument ("-NoProfile -WindowStyle Hidden -ExecutionPolicy Bypass -File `"$agent`" -RefreshNow -WatchSeconds 30") `
            -WorkingDirectory $root

        # Do not bind the trigger to $env:USERNAME. Microsoft-account, AzureAD,
        # domain, and elevated shells can expose a username string which Task
        # Scheduler cannot resolve even though the current user is valid.
        $trigger = New-ScheduledTaskTrigger -AtLogOn
        $settings = New-ScheduledTaskSettingsSet `
            -AllowStartIfOnBatteries `
            -DontStopIfGoingOnBatteries `
            -StartWhenAvailable `
            -RestartCount 5 `
            -RestartInterval (New-TimeSpan -Minutes 1) `
            -ExecutionTimeLimit (New-TimeSpan -Days 3650)

        Register-ScheduledTask `
            -TaskName $taskName `
            -Action $action `
            -Trigger $trigger `
            -Settings $settings `
            -Description "Aetheris HostDrive Agent - keeps localhost drive helper online and refreshes Docker mounts for attached drives." `
            -Force | Out-Null

        Write-Host "Registered scheduled task: $taskName"
        try {
            Start-ScheduledTask -TaskName $taskName -ErrorAction Stop
            Start-Sleep -Seconds 2
            $task = Get-ScheduledTask -TaskName $taskName -ErrorAction Stop
            Write-Host "Scheduled task state: $($task.State)"
            if ($task.State -eq 'Running') {
                Remove-StartupFolderFallback
                return $true
            }
            Write-Warning "Scheduled task registered but is not Running; using process fallback for this session."
            return $false
        }
        catch {
            Write-Warning ("Scheduled task registered but could not be started now: {0}" -f $_.Exception.Message)
            return $false
        }
    }
    catch {
        Write-Warning ("Scheduled Task registration unavailable: {0}" -f $_.Exception.Message)
        return $false
    }
}

Stop-OldAgentInstances

try {
    Register-HostDriveProtocol
}
catch {
    Write-Warning ("Protocol registration failed: {0}" -f $_.Exception.Message)
}

Write-Host "Ensuring HostDrive helper..."
& powershell.exe -NoProfile -ExecutionPolicy Bypass -File $ensure
$ensureExit = $LASTEXITCODE
if ($ensureExit -ne 0) {
    Write-Warning "HostDrive helper bootstrap returned exit code $ensureExit. Deployment will verify localhost health separately."
}

# A refresh failure here can simply mean an external drive needs the WSL bridge,
# which is handled by the v4 refresh job. Do not treat it as an installation error.
Write-Host "Running one-shot drive refresh..."
& powershell.exe -NoProfile -WindowStyle Hidden -ExecutionPolicy Bypass -File $agent -RefreshNow -Once
$oneShotExit = $LASTEXITCODE
if ($oneShotExit -ne 0) {
    Write-Warning "Initial one-shot refresh returned exit code $oneShotExit; continuing so exact-path recovery can run."
}

$taskRunning = Try-RegisterScheduledWatcher
if (-not $taskRunning) {
    $startupOk = Install-StartupFolderFallback
    $processOk = Start-HiddenAgentFallback
    if (-not $startupOk -and -not $processOk) {
        # The app can still perform an exact refresh through the localhost helper.
        # Report a warning, but do not make installation a deployment blocker.
        Write-Warning "Automatic background watcher could not be installed. Exact in-app refresh remains available for this session."
    }
}

Write-Host ""
Write-Host "HostDrive agent installation stage complete."
Write-Host "  Helper URL:  http://127.0.0.1:9876/health"
Write-Host "  Protocol:    aetheris-hostdrive:refresh"
Write-Host "  Manual:      powershell -ExecutionPolicy Bypass -File scripts\hostdrive-agent.ps1 -RefreshNow -Once"
exit 0
