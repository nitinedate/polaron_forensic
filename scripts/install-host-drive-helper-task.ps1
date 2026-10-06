# Install Aetheris host drive helper to start automatically at Windows logon.
# Run once on the examiner workstation (admin not required):
#   powershell -ExecutionPolicy Bypass -File scripts\install-host-drive-helper-task.ps1

$ErrorActionPreference = "Stop"
$root = Split-Path -Parent (Split-Path -Parent $MyInvocation.MyCommand.Path)
$ensure = Join-Path $root "scripts\ensure-host-drive-helper.ps1"
$taskName = "AetherisHostDriveHelper"

function Install-StartupFolderFallback {
    $startup = [Environment]::GetFolderPath("Startup")
    $launcher = Join-Path $startup "AetherisHostDriveHelper.cmd"
    $content = @"
@echo off
powershell.exe -NoProfile -WindowStyle Hidden -ExecutionPolicy Bypass -File "$ensure"
"@
    Set-Content -Path $launcher -Value $content -Encoding ASCII
    Write-Host "Registered Startup folder launcher: $launcher"
}

$action = New-ScheduledTaskAction `
    -Execute "powershell.exe" `
    -Argument "-NoProfile -WindowStyle Hidden -ExecutionPolicy Bypass -File `"$ensure`"" `
    -WorkingDirectory $root

$trigger = New-ScheduledTaskTrigger -AtLogOn -User $env:USERNAME

$settings = New-ScheduledTaskSettingsSet `
    -AllowStartIfOnBatteries `
    -DontStopIfGoingOnBatteries `
    -StartWhenAvailable `
    -RestartCount 3 `
    -RestartInterval (New-TimeSpan -Minutes 1)

$taskRegistered = $false
try {
    Register-ScheduledTask `
        -TaskName $taskName `
        -Action $action `
        -Trigger $trigger `
        -Settings $settings `
        -Description "Starts Aetheris host drive helper (port 9876) for forensic UI folder browse and Docker drive mounts." `
        -Force | Out-Null
    $taskRegistered = $true
    Write-Host "Registered scheduled task: $taskName (runs at logon for $env:USERNAME)"
} catch {
    Write-Warning "Could not register scheduled task ($($_.Exception.Message)). Using Startup folder fallback."
    Install-StartupFolderFallback
}

Write-Host "Starting helper now..."
& $ensure
if ($LASTEXITCODE -eq 0) {
    Write-Host "Host drive helper is online."
} else {
    Write-Host "Helper did not respond yet - run ensure-host-drive-helper.ps1 manually or log off/on after install."
}

if ($taskRegistered) {
    exit 0
}
exit $LASTEXITCODE
