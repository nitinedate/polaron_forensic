# One-click repair and verification for Android/iPhone detection in the Device Wizard.
# Run from the Aetheris project root:
#   powershell -NoProfile -ExecutionPolicy Bypass -File scripts\repair-mobile-usb.ps1
param(
    [switch]$ForceKit,
    [int]$Port = $(if ($env:HOST_DRIVE_HELPER_PORT) { [int]$env:HOST_DRIVE_HELPER_PORT } else { 9876 })
)

$ErrorActionPreference = "Continue"
$root = Split-Path -Parent (Split-Path -Parent $MyInvocation.MyCommand.Path)
$ensure = Join-Path $root "scripts\ensure-host-drive-helper.ps1"
$kit = Join-Path $root "scripts\ensure-examiner-kit.ps1"
$networkConfig = Join-Path $root "scripts\configure-host-drive-helper-network.ps1"
$installTask = Join-Path $root "scripts\install-host-drive-helper-task.ps1"
$stateDir = Join-Path $env:LOCALAPPDATA "Aetheris"
$helperErrLog = Join-Path $stateDir "host-drive-helper.err.log"
$helperOutLog = Join-Path $stateDir "host-drive-helper.out.log"

function Test-IsAdministrator {
    try {
        $identity = [Security.Principal.WindowsIdentity]::GetCurrent()
        $principal = New-Object Security.Principal.WindowsPrincipal($identity)
        return $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
    }
    catch { return $false }
}

# Repairing the wildcard HttpListener URL ACL and Windows firewall is a one-time
# administrative operation. Self-elevate so double-clicking Repair-Mobile-USB.cmd
# is sufficient; users do not have to remember to open an Administrator shell.
if (-not (Test-IsAdministrator)) {
    Write-Host "Administrator access is required once to repair the HostDrive USB bridge." -ForegroundColor Yellow
    Write-Host "A Windows UAC prompt will open now." -ForegroundColor Yellow
    $args = @(
        "-NoProfile", "-ExecutionPolicy", "Bypass",
        "-File", ('"' + $MyInvocation.MyCommand.Path + '"'),
        "-Port", ([string]$Port)
    )
    if ($ForceKit) { $args += "-ForceKit" }
    try {
        $elevated = Start-Process -FilePath "powershell.exe" -Verb RunAs -ArgumentList $args -Wait -PassThru
        exit $elevated.ExitCode
    }
    catch {
        Write-Host "Elevation was cancelled or failed: $($_.Exception.Message)" -ForegroundColor Red
        exit 5
    }
}

function Write-Step([string]$Message) {
    Write-Host ""
    Write-Host "==> $Message" -ForegroundColor Cyan
}

Write-Host "Aetheris mobile USB repair" -ForegroundColor Green
Write-Host "Project: $root"

if ($ForceKit -and (Test-Path -LiteralPath $kit)) {
    Write-Step "Refreshing examiner USB tools"
    & powershell.exe -NoProfile -ExecutionPolicy Bypass -File $kit -Force
}

Write-Step "Repairing Windows URL reservation and Docker/WSL firewall rule"
if (Test-Path -LiteralPath $networkConfig) {
    & powershell.exe -NoProfile -ExecutionPolicy Bypass -File $networkConfig -Port $Port
    if ($LASTEXITCODE -ne 0) {
        Write-Host "FAILED: could not configure HostDrive network access (exit $LASTEXITCODE)." -ForegroundColor Red
        exit 6
    }
}

Write-Step "Starting/restarting HostDrive mobile helper"
& powershell.exe -NoProfile -ExecutionPolicy Bypass -File $ensure -ForceRestart

$health = $null
try { $health = Invoke-RestMethod -Uri "http://127.0.0.1:$Port/health" -TimeoutSec 5 } catch { }
if (-not $health -or -not [bool]$health.ok) {
    Write-Host "FAILED: helper is not reachable on 127.0.0.1:$Port" -ForegroundColor Red
    foreach ($logPath in @($helperErrLog, $helperOutLog)) {
        if (Test-Path -LiteralPath $logPath) {
            Write-Host "--- $logPath ---" -ForegroundColor DarkGray
            Get-Content -LiteralPath $logPath -Tail 50 -ErrorAction SilentlyContinue | ForEach-Object { Write-Host $_ }
        }
    }
    Write-Host "The most common causes are a stale URL ACL or a project path containing spaces. This V17 repair handles both automatically." -ForegroundColor Yellow
    exit 2
}
Write-Host ("Helper OK: pid={0}, bind={1}, root={2}" -f $health.helper_pid, $health.bind_host, $health.root) -ForegroundColor Green

Write-Step "Checking host adapters"
$adapters = $null
try { $adapters = Invoke-RestMethod -Uri "http://127.0.0.1:$Port/acquisition/adapters" -TimeoutSec 10 } catch { }
if ($adapters -and $adapters.adapters) {
    $adapters.adapters | Format-Table name, available, reason -AutoSize
}

Write-Step "Checking devices seen by Windows host"
$hostDevices = $null
try { $hostDevices = Invoke-RestMethod -Uri "http://127.0.0.1:$Port/acquisition/devices" -TimeoutSec 20 } catch { }
if ($hostDevices -and $hostDevices.devices -and $hostDevices.devices.Count -gt 0) {
    $hostDevices.devices | Format-Table adapter, device_id, label, status, connection -AutoSize
} else {
    Write-Host "No phone detected by the Windows host helper yet." -ForegroundColor Yellow
}
if ($hostDevices -and $hostDevices.warnings) {
    foreach ($w in @($hostDevices.warnings)) { Write-Host "  - $w" -ForegroundColor Yellow }
}

Write-Step "Checking Android ADB state"
$adb = Join-Path $root "tools\platform-tools\adb.exe"
if (Test-Path -LiteralPath $adb) {
    try { & $adb kill-server 2>$null | Out-Null } catch { }
    try { & $adb start-server 2>$null | Out-Null } catch { }
    $adbLines = @(& $adb devices -l 2>$null)
    $adbLines | ForEach-Object { Write-Host $_ }
    $unauthorized = @($adbLines | Where-Object { "$_" -match '\sunauthorized(\s|$)' })
    $offline = @($adbLines | Where-Object { "$_" -match '\soffline(\s|$)' })
    if ($unauthorized.Count) {
        Write-Host "ACTION ON PHONE: unlock it and tap 'Allow USB debugging'. Tick 'Always allow from this computer' if appropriate." -ForegroundColor Yellow
    }
    if ($offline.Count) {
        Write-Host "ACTION: unplug/replug the USB cable, set USB mode to File transfer/MTP, then run this script again." -ForegroundColor Yellow
    }
} else {
    Write-Host "adb.exe is missing. Re-run with -ForceKit or use MTP/File transfer mode." -ForegroundColor Yellow
}

Write-Step "Checking Windows phone / MTP driver state"
try {
    $phonePnp = @(Get-PnpDevice -PresentOnly -ErrorAction SilentlyContinue | Where-Object {
        ([string]$_.Class -match 'WPD|USB|USBDevice|AndroidUsbDeviceClass') -and
        ([string]$_.FriendlyName -match '(?i)Android|MTP|Portable|Samsung|Galaxy|Xiaomi|Redmi|POCO|Huawei|Honor|OnePlus|Pixel|Motorola|Moto|Nokia|Oppo|Vivo|Realme|Tecno|Infinix|Nothing|Sony|Xperia|ADB')
    })
    if ($phonePnp.Count -gt 0) {
        $phonePnp | Select-Object Status, Class, FriendlyName, InstanceId | Format-Table -AutoSize
        $bad = @($phonePnp | Where-Object { $_.Status -ne 'OK' })
        if ($bad.Count -gt 0) {
            Write-Host "One or more Android USB devices have a Windows driver problem. Open Device Manager and update/reinstall the MTP/OEM ADB driver for the entries shown above." -ForegroundColor Yellow
        }
    } else {
        Write-Host "Windows PnP does not currently list an Android/MTP device. Check the USB data cable and select File transfer / MTP on the phone." -ForegroundColor Yellow
    }
} catch {
    Write-Host "Could not enumerate Windows phone drivers: $($_.Exception.Message)" -ForegroundColor Yellow
}

Write-Step "Checking Docker -> Windows helper bridge"
$docker = Get-Command docker.exe -ErrorAction SilentlyContinue
if (-not $docker) { $docker = Get-Command docker -ErrorAction SilentlyContinue }
if (-not $docker) {
    Write-Host "Docker CLI not found; host-side checks completed." -ForegroundColor Yellow
    exit 0
}

$apiId = $null
try {
    $apiId = (& $docker.Source ps --filter "label=com.docker.compose.service=api" --format "{{.ID}}" 2>$null | Where-Object { $_ } | Select-Object -First 1)
} catch { }
if (-not $apiId) {
    Write-Host "No running Aetheris API container found. Start the stack, then run this script again." -ForegroundColor Yellow
    exit 0
}

$py = @'
import json, urllib.request
for path in ("/health", "/acquisition/adapters", "/acquisition/devices"):
    url = "http://host.docker.internal:9876" + path
    try:
        with urllib.request.urlopen(url, timeout=5) as r:
            data = json.loads(r.read().decode("utf-8", "replace"))
        print(path, "OK", json.dumps(data, ensure_ascii=False)[:1500])
    except Exception as e:
        print(path, "ERROR", repr(e))
        raise
'@
& $docker.Source exec $apiId python -c $py
if ($LASTEXITCODE -ne 0) {
    Write-Host "Docker cannot reach the Windows helper." -ForegroundColor Red
    Write-Host "Run this command once from Administrator PowerShell, then rerun this repair:" -ForegroundColor Yellow
    Write-Host "  powershell -ExecutionPolicy Bypass -File scripts\configure-host-drive-helper-network.ps1" -ForegroundColor White
    exit 3
}

Write-Step "Installing HostDrive helper automatic startup"
if (Test-Path -LiteralPath $installTask) {
    try {
        & powershell.exe -NoProfile -ExecutionPolicy Bypass -File $installTask
        if ($LASTEXITCODE -ne 0) {
            Write-Host "Autostart registration returned exit $LASTEXITCODE; current USB session is still usable." -ForegroundColor Yellow
        }
    } catch {
        Write-Host "Autostart registration warning: $($_.Exception.Message)" -ForegroundColor Yellow
    }
}

Write-Host ""
Write-Host "SUCCESS: Host helper, Android tooling, and Docker bridge are ready." -ForegroundColor Green
Write-Host "In the UI click Scan for devices again." -ForegroundColor Green
if (-not $hostDevices -or -not $hostDevices.devices -or $hostDevices.devices.Count -eq 0) {
    Write-Host "If Android still does not appear: use a DATA cable, unlock the phone, set USB to File transfer/MTP, and enable USB debugging if using ADB." -ForegroundColor Yellow
}
exit 0
