# Localhost helper for the Forensic UI - regenerates drive bind mounts and recreates api/worker.
# Run on the Windows examiner workstation (not inside Docker):
#   powershell -ExecutionPolicy Bypass -File scripts/host-drive-helper.ps1
#
# Optional env:
#   HOST_DRIVE_HELPER_PORT=9876
#   HOST_DRIVE_HELPER_BIND_HOST=+    (+ lets Docker Desktop reach the Windows host helper)
#   HOST_DRIVE_HELPER_TOKEN=secret   (require X-Host-Helper-Token header when set)

param(
    [int]$Port = $(if ($env:HOST_DRIVE_HELPER_PORT) { [int]$env:HOST_DRIVE_HELPER_PORT } else { 9876 }),
    [string]$BindHost = $(if ($env:HOST_DRIVE_HELPER_BIND_HOST) { [string]$env:HOST_DRIVE_HELPER_BIND_HOST } else { "+" })
)

$ErrorActionPreference = "Stop"
$root = Split-Path -Parent (Split-Path -Parent $MyInvocation.MyCommand.Path)
$generateScript = Join-Path $root "scripts\generate-drive-mounts.ps1"
$composeBase = Join-Path $root "docker-compose.yml"
$composeDrives = Join-Path $root "docker-compose.drives.generated.yml"
$expectedToken = $env:HOST_DRIVE_HELPER_TOKEN
$acquireScript = Join-Path $root "scripts\host-mobile-acquire.ps1"
if (Test-Path -LiteralPath $acquireScript) {
    . $acquireScript
}

function Test-PythonExe {
    param([string]$Exe)
    if (-not $Exe -or -not (Test-Path -LiteralPath $Exe)) { return $false }
    try {
        $tag = [guid]::NewGuid().ToString("N")
        $out = Join-Path $env:TEMP ("aetheris_pyok_" + $tag + ".out")
        $err = Join-Path $env:TEMP ("aetheris_pyok_" + $tag + ".err")
        $proc = Start-Process -FilePath $Exe -ArgumentList @("-c", "print(1)") -PassThru -WindowStyle Hidden `
            -RedirectStandardOutput $out -RedirectStandardError $err
        if (-not $proc.WaitForExit(2000)) {
            try { $proc.Kill() } catch {}
            Remove-Item -LiteralPath $out, $err -Force -ErrorAction SilentlyContinue
            return $false
        }
        $ok = ($proc.ExitCode -eq 0)
        Remove-Item -LiteralPath $out, $err -Force -ErrorAction SilentlyContinue
        return $ok
    } catch { return $false }
}

function Get-HostPython {
    foreach ($c in @(
        (Join-Path $root "backend\.venv\Scripts\python.exe"),
        (Join-Path $root ".venv\Scripts\python.exe"),
        (Join-Path $root "tools\host-python\Scripts\python.exe")
    )) {
        if ($c -match '(?i)WindowsApps') { continue }
        if (Test-PythonExe $c) { return $c }
    }
    $cmd = Get-Command python -ErrorAction SilentlyContinue
    if ($cmd -and $cmd.Source -and $cmd.Source -notmatch '(?i)WindowsApps' -and (Test-PythonExe $cmd.Source)) {
        return $cmd.Source
    }
    return $null
}

function New-HostDevicePreview {
    param([string]$Adapter, [string]$DeviceId, [string]$NameHint = "")
    $os = "android"
    if ($Adapter -match 'ios') { $os = "ios" }
    $name = $(if ($NameHint) { $NameHint } else { $DeviceId })
    if ($name -match '(?i)iPhone|iPad|iPod|Apple') { $os = "ios" }
    elseif ($name -match '(?i)Android|Samsung|Galaxy|Pixel|Xiaomi|Huawei|Honor|OnePlus|Oppo|Vivo') { $os = "android" }
    $logicalOnly = ($Adapter -match 'mtp' -or $Adapter -eq "android_mtp")
    $methods = if ($os -eq "ios") { @("backup", "advanced_logical", "logical") } else { @("logical", "advanced_logical", "backup", "file_system", "full_file_system") }
    $manufacturer = if ($os -eq "ios") { "Apple" } elseif ($name -match '(?i)Samsung|Galaxy') { "Samsung" } elseif ($name -match '(?i)Oppo') { "OPPO" } else { "" }
    $lockState = if ($logicalOnly) { "unlocked_for_mtp" } else { "unknown" }
    $label = "SUPPORTED_DIRECT_LOGICAL"
    return @{
        ok = $true
        device_profile = @{
            manufacturer = $manufacturer
            model = $name
            device_label = $name
            chipset = ""
            serial = $DeviceId
            imei = ""
            udid = $(if ($os -eq "ios") { $DeviceId } else { "" })
            os_family = $os
            os_version = ""
            security_patch_level = ""
            build_id = ""
            lock_state = $lockState
            encryption_state = "unknown"
            connection_mode = $(if ($logicalOnly) { "mtp" } else { "usb" })
            usb_debugging_authorized = [bool]($Adapter -eq "android_adb")
            pairing_trusted = [bool]($os -eq "ios")
            developer_mode = $false
            rooted_or_jailbroken = $null
            battery_percent = $null
            network_isolated = $null
            sim_present = $null
            iccid = ""
            imsi = ""
            sd_card_present = $null
            sd_card_identifier = ""
            tool_version = "aetheris-acquire/host-helper"
            license_entitlements = @()
            required_cable = "USB data cable"
            unknown_fields = @()
            observations = @(
                "Detected on the examiner Windows host over USB (no extra adapter).",
                $(if ($logicalOnly) { "MTP / file-transfer collection of shared storage, recycle-bin folders, and chat media. Enable USB debugging for ADB backup of app databases." } else { "Host USB collection via the HostDrive helper." })
            )
        }
        capability = @{
            capability_label = $label
            supported_methods = $methods
            blocked_methods = @{}
            warnings = @()
            preparation_steps = @(
                "Keep the phone unlocked and the data cable seated.",
                $(if ($os -eq "ios") { "Tap Trust This Computer if prompted." } else { "Use File transfer / MTP if the phone asks." })
            )
        }
        preparation_steps = @(
            "Keep the phone unlocked and the data cable seated.",
            $(if ($os -eq "ios") { "Tap Trust This Computer if prompted." } else { "Use File transfer / MTP if the phone asks." })
        )
        method_profiles = @{}
    }
}

function Write-AcquireJobSidecar {
    param(
        [string]$JobId,
        [int]$ProcessId,
        [string]$ResultFile,
        [string]$ProgressFile,
        [string]$CaseId = ""
    )
    $dir = Join-Path $env:TEMP "aetheris_acq_jobs"
    New-Item -ItemType Directory -Force -Path $dir | Out-Null
    $meta = @{
        pid           = $ProcessId
        result_file   = $ResultFile
        progress_file = $ProgressFile
        status        = "running"
        started_utc   = (Get-Date).ToUniversalTime().ToString("o")
        case_id       = $CaseId
    }
    [System.IO.File]::WriteAllText(
        (Join-Path $dir ($JobId + ".json")),
        ($meta | ConvertTo-Json -Compress),
        [System.Text.UTF8Encoding]::new($false)
    )
}

function Start-NativeMtpAcquireJob {
    param(
        [hashtable]$RunPayload,
        [string]$Stamp,
        [string]$TmpResult
    )
    $jobPs1 = Join-Path $root "scripts\native_mtp_job.ps1"
    $payloadFile = Join-Path $env:TEMP ("acq_mtp_" + $Stamp + ".json")
    [System.IO.File]::WriteAllText($payloadFile, ($RunPayload | ConvertTo-Json -Depth 20), [System.Text.UTF8Encoding]::new($false))
    $script:Busy = $true
    $script:AcquireBusy = $true
    $argList = @(
        "-STA", "-NoProfile", "-ExecutionPolicy", "Bypass",
        "-File", $jobPs1,
        "-PayloadFile", $payloadFile,
        "-ResultFile", $TmpResult
    )
    $proc = Start-Process -FilePath "powershell.exe" -ArgumentList $argList -WorkingDirectory $root `
        -WindowStyle Minimized -PassThru
    Write-AcquireJobSidecar -JobId $Stamp -ProcessId $proc.Id -ResultFile $TmpResult -ProgressFile ([string]$RunPayload.progress_file) -CaseId ([string]$RunPayload.case_id)
    $script:AcquireJobs[$Stamp] = @{
        Pid          = $proc.Id
        ResultFile   = $TmpResult
        ProgressFile = [string]$RunPayload.progress_file
        ErrFile      = ""
        OutFile      = ""
        Status       = "running"
        Error        = ""
        StartedUtc   = (Get-Date).ToUniversalTime().ToString("o")
    }
}

function Find-AdbExe {
    $wingetRoot = Join-Path $env:LOCALAPPDATA "Microsoft\WinGet\Packages"
    $candidates = @(
        (Join-Path $root "tools\platform-tools\adb.exe"),
        (Join-Path $env:LOCALAPPDATA "Android\Sdk\platform-tools\adb.exe"),
        (Join-Path $env:LOCALAPPDATA "Microsoft\WinGet\Links\adb.exe"),
        "C:\Android\platform-tools\adb.exe",
        "C:\platform-tools\adb.exe"
    )
    foreach ($p in $candidates) {
        if ($p -and (Test-Path -LiteralPath $p)) { return $p }
    }
    if (Test-Path -LiteralPath $wingetRoot) {
        $hit = Get-ChildItem -LiteralPath $wingetRoot -Filter "adb.exe" -Recurse -ErrorAction SilentlyContinue |
            Select-Object -First 1
        if ($hit) { return $hit.FullName }
    }
    $cmd = Get-Command "adb.exe" -ErrorAction SilentlyContinue
    if ($cmd) { return $cmd.Source }
    return $null
}

function Get-IosUsbmuxDevices {
    $script:LastUsbmuxError = $null
    $listScript = Join-Path $root "scripts\ios_usbmux_list.py"
    $py = Get-HostPython
    if (-not $py -or -not (Test-Path -LiteralPath $listScript)) {
        $script:LastUsbmuxError = "examiner kit python or ios_usbmux_list.py missing"
        return @()
    }
    try {
        $prev = $env:PYTHONPATH
        $env:PYTHONPATH = (Join-Path $root "backend")
        $raw = & $py $listScript 2>$null | Out-String
        $env:PYTHONPATH = $prev
        if (-not $raw) { return @() }
        $jsonLine = ($raw -split "`r?`n" | Where-Object { $_.Trim().StartsWith("{") } | Select-Object -Last 1)
        if (-not $jsonLine) { return @() }
        $obj = $jsonLine | ConvertFrom-Json
        if ($obj.error) { $script:LastUsbmuxError = [string]$obj.error }
        if (-not $obj.ok) { return @() }
        return @($obj.devices)
    }
    catch {
        $script:LastUsbmuxError = $_.Exception.Message
        return @()
    }
}

function Find-IdeviceIdExe {
    $candidates = @(
        (Join-Path $root "tools\libimobiledevice\idevice_id.exe"),
        "C:\Program Files\libimobiledevice\idevice_id.exe",
        "C:\tools\libimobiledevice\idevice_id.exe"
    )
    foreach ($p in $candidates) {
        if ($p -and (Test-Path -LiteralPath $p)) { return $p }
    }
    if (Get-Command Find-HostTool -ErrorAction SilentlyContinue) {
        $found = Find-HostTool -Names @("idevice_id.exe", "idevice_id")
        if ($found) { return $found }
    }
    $cmd = Get-Command "idevice_id.exe" -ErrorAction SilentlyContinue
    if ($cmd) { return $cmd.Source }
    return $null
}

$script:LastUsbmuxError = $null
$script:Busy = $false
$script:AcquireBusy = $false
$script:PendingAcquire = $null
# Async acquire jobs: job_id -> @{ Pid; ResultFile; ProgressFile; Status; Error; StartedUtc }
$script:AcquireJobs = @{}
# Async drive-mount refresh (keeps /health responsive while docker compose runs)
$script:RefreshStatusFile = Join-Path $env:TEMP ("aetheris_drive_refresh_{0}.json" -f $PID)
$script:RefreshProcess = $null
$refreshJobScript = Join-Path $root "scripts\refresh-drive-mounts-job.ps1"
$script:HelperVersion = "5.36"
$script:DeviceCacheAt = [datetime]::MinValue
$script:DeviceCache = @()
$script:DeviceScanBusy = $false
$script:DeviceCacheFile = Join-Path $env:TEMP "aetheris_host_mobile_devices.json"
$script:AdaptersCacheFile = Join-Path $env:TEMP "aetheris_host_acquisition_adapters.json"
$script:AcqDevicesCacheFile = Join-Path $env:TEMP "aetheris_host_acquisition_devices.json"
$script:DeviceRefreshJob = $null
$script:DriveCacheAt = [datetime]::MinValue
$script:DriveCache = @()
$script:HelperStartedUtc = (Get-Date).ToUniversalTime().ToString("o")

function Get-JobScriptVersion {
    # Read the version marker from the job script currently on disk so /health
    # reflects what a refresh would actually run.
    try {
        if (-not (Test-Path -LiteralPath $refreshJobScript)) { return $null }
        $head = Get-Content -LiteralPath $refreshJobScript -TotalCount 40 -ErrorAction Stop
        foreach ($line in @($head)) {
            if (("$line") -match 'AETHERIS_JOB_VERSION:\s*([0-9][0-9A-Za-z.\-]*)') { return $Matches[1] }
        }
        return "legacy"
    }
    catch { return $null }
}

function Write-RawJsonResponse {
    param(
        [System.Net.HttpListenerResponse]$Response,
        [int]$StatusCode,
        [string]$Json
    )

    if ($null -eq $Json) { $Json = "{}" }
    $bytes = [System.Text.Encoding]::UTF8.GetBytes($Json)
    $Response.StatusCode = $StatusCode
    $Response.ContentType = "application/json; charset=utf-8"
    $Response.Headers["Access-Control-Allow-Origin"] = "*"
    $Response.Headers["Access-Control-Allow-Methods"] = "GET, POST, OPTIONS"
    $Response.Headers["Access-Control-Allow-Headers"] = "Content-Type, X-Host-Helper-Token"
    $Response.ContentLength64 = $bytes.Length
    $Response.OutputStream.Write($bytes, 0, $bytes.Length)
    $Response.OutputStream.Close()
}

function Write-JsonResponse {
    param(
        [System.Net.HttpListenerResponse]$Response,
        [int]$StatusCode,
        [object]$Body
    )

    # Depth 20 for nested cloud_mailboxes / evidence packages; still avoid for huge acquire results.
    $json = $Body | ConvertTo-Json -Compress -Depth 20
    Write-RawJsonResponse -Response $Response -StatusCode $StatusCode -Json $json
}

function Stop-AcquireJob {
    param(
        [string]$JobId = "",
        [string]$ProgressFile = ""
    )

    $stopped = New-Object System.Collections.Generic.List[string]
    $ids = @()
    if ($JobId -and $script:AcquireJobs.ContainsKey($JobId)) {
        $ids = @($JobId)
    }
    else {
        $ids = @($script:AcquireJobs.Keys | Where-Object {
            $script:AcquireJobs[$_].Status -eq "running"
        })
    }

    foreach ($id in $ids) {
        $job = $script:AcquireJobs[$id]
        $prog = [string]$job.ProgressFile
        if ($ProgressFile) { $prog = $ProgressFile }
        if ($prog) {
            try {
                Set-Content -LiteralPath ($prog + ".cancel") -Value "cancel" -Encoding UTF8
            } catch {}
            try {
                @{
                    stage      = "cancelled"
                    item       = "cancelled"
                    detail     = "Stopped by examiner"
                    category   = "Cancelled"
                    bytes_done = 0
                } | ConvertTo-Json -Compress | Set-Content -LiteralPath $prog -Encoding UTF8
            } catch {}
        }
        if ($job.Pid) {
            & taskkill.exe /PID ([int]$job.Pid) /T /F 2>$null | Out-Null
        }
        $job.Status = "cancelled"
        $script:AcquireJobs[$id] = $job
        $stopped.Add($id) | Out-Null
    }

    # Orphans from a previous helper still writing an iPhone backup.
    try {
        Get-CimInstance Win32_Process -Filter "Name='python.exe' OR Name='pythonw.exe'" -ErrorAction SilentlyContinue |
            Where-Object { $_.CommandLine -and $_.CommandLine -match 'acq_run_|ios_usbmux_backup|native_ios_job|native_mtp_job|host-mobile-acquire' } |
            ForEach-Object {
                & taskkill.exe /PID $_.ProcessId /T /F 2>$null | Out-Null
            }
    } catch {}
    try {
        Get-CimInstance Win32_Process -Filter "Name='powershell.exe' OR Name='pwsh.exe'" -ErrorAction SilentlyContinue |
            Where-Object {
                $_.CommandLine -and
                $_.CommandLine -notmatch 'host-drive-helper' -and
                $_.CommandLine -match 'native_ios_job|native_mtp_job|host-mobile-acquire'
            } |
            ForEach-Object {
                & taskkill.exe /PID $_.ProcessId /T /F 2>$null | Out-Null
            }
    } catch {}

    # Native C# sidecar jobs (MTP / iOS) are not in $script:AcquireJobs.
    $jobsDir = Join-Path $env:TEMP "aetheris_acq_jobs"
    if (Test-Path -LiteralPath $jobsDir) {
        $sidecarFiles = @()
        if ($JobId) {
            $one = Join-Path $jobsDir ($JobId + ".json")
            if (Test-Path -LiteralPath $one) { $sidecarFiles = @($one) }
        } else {
            $sidecarFiles = @(Get-ChildItem -LiteralPath $jobsDir -Filter "*.json" -ErrorAction SilentlyContinue | ForEach-Object { $_.FullName })
        }
        foreach ($metaPath in $sidecarFiles) {
            try {
                $meta = Get-Content -LiteralPath $metaPath -Raw -Encoding UTF8 | ConvertFrom-Json
                $sid = [int]($(if ($meta.pid) { $meta.pid } else { 0 }))
                if ($sid -gt 0) {
                    $alive = Get-Process -Id $sid -ErrorAction SilentlyContinue
                    if ($alive) {
                        & taskkill.exe /PID $sid /T /F 2>$null | Out-Null
                    }
                    $stopped.Add(([IO.Path]::GetFileNameWithoutExtension($metaPath))) | Out-Null
                }
                $prog = [string]$meta.progress_file
                if ($prog) {
                    try {
                        Set-Content -LiteralPath ($prog + ".cancel") -Value "cancel" -Encoding UTF8
                    } catch {}
                }
            } catch {}
        }
    }

    $script:Busy = $false
    $script:AcquireBusy = $false
    return @{
        ok        = $true
        cancelled = @($stopped)
        message   = "Host collection stopped"
    }
}

function _Add-SafeAcquirePath {
    param($Bag, [string]$Path)
    if (-not $Path) { return }
    $p = [string]$Path
    if ($p.Length -lt 8) { return }
    if ($p -match '^[\\/]evidence') { return }
    if (-not (Test-Path -LiteralPath $p)) { return }
    [void]$Bag.Add($p)
}

function Remove-AcquireRunData {
    param(
        [string]$JobId = "",
        [string]$RunName = "",
        [string]$CaseId = "",
        [string]$ProgressFile = "",
        [hashtable]$ExtraPaths = @{}
    )
    $stop = Stop-AcquireJob -JobId $JobId -ProgressFile $ProgressFile
    $removed = New-Object System.Collections.Generic.List[string]
    $candidates = New-Object System.Collections.Generic.List[string]

    $job = $null
    if ($JobId -and $script:AcquireJobs.ContainsKey($JobId)) {
        $job = $script:AcquireJobs[$JobId]
    }
    $progFile = $ProgressFile
    $resultFile = ""
    if ($job) {
        if (-not $progFile) { $progFile = [string]$job.ProgressFile }
        $resultFile = [string]$job.ResultFile
    }
    $sidecar = Join-Path (Join-Path $env:TEMP "aetheris_acq_jobs") ($JobId + ".json")
    if ((-not $progFile -or -not $resultFile) -and $JobId -and (Test-Path -LiteralPath $sidecar)) {
        try {
            $meta = Get-Content -LiteralPath $sidecar -Raw -Encoding UTF8 | ConvertFrom-Json
            if (-not $progFile) { $progFile = [string]$meta.progress_file }
            if (-not $resultFile) { $resultFile = [string]$meta.result_file }
            if (-not $CaseId) { $CaseId = [string]$meta.case_id }
        } catch {}
    }

    $objs = @()
    foreach ($f in @($progFile, $resultFile)) {
        if ($f -and (Test-Path -LiteralPath $f)) {
            try { $objs += (Get-Content -LiteralPath $f -Raw -Encoding UTF8 | ConvertFrom-Json) } catch {}
        }
    }
    foreach ($o in $objs) {
        if (-not $RunName -and $o.run_name) { $RunName = [string]$o.run_name }
        $paths = $o.paths
        if ($paths) {
            foreach ($k in @("original", "working", "logs", "hashes", "exports", "case_root")) {
                _Add-SafeAcquirePath $candidates ([string]$paths.$k)
            }
        }
        foreach ($k in @("output_path", "media_path", "case_path")) {
            if ($o.$k) { _Add-SafeAcquirePath $candidates ([string]$o.$k) }
            if ($o.progress -and $o.progress.$k) { _Add-SafeAcquirePath $candidates ([string]$o.progress.$k) }
        }
        $serial = ""
        if ($o.device -and $o.device.serial) { $serial = [string]$o.device.serial }
        if (-not $serial -and $o.device_id) { $serial = [string]$o.device_id }
        $digits = ($serial -replace '[^0-9A-Fa-f]', '')
        if ($digits.Length -ge 8) {
            $tail = $digits.Substring($digits.Length - 8)
            foreach ($letter in @("E", "D", "C")) {
                _Add-SafeAcquirePath $candidates (Join-Path "${letter}:\ib" $tail)
            }
        }
    }
    foreach ($k in @("original", "working", "logs", "hashes", "exports", "case_root", "output_path")) {
        if ($ExtraPaths.$k) { _Add-SafeAcquirePath $candidates ([string]$ExtraPaths.$k) }
    }

    if ($RunName) {
        $safeName = $RunName -replace '[^\w\-.]', '_'
        foreach ($base in $candidates) {
            $parent = if (Test-Path -LiteralPath $base -PathType Container) { $base } else { Split-Path -Parent $base }
            $caseDir = $parent
            for ($i = 0; $i -lt 4; $i++) {
                if ((Split-Path -Leaf $caseDir) -match '^CASE-') { break }
                $up = Split-Path -Parent $caseDir
                if (-not $up -or $up -eq $caseDir) { break }
                $caseDir = $up
            }
            foreach ($sub in @("02_Original_Extraction", "03_Working_Copy", "05_Exports", "07_Logs", "08_Hashes")) {
                _Add-SafeAcquirePath $candidates (Join-Path (Join-Path $caseDir $sub) $safeName)
            }
        }
        if ($CaseId) {
            $caseRoot = Join-Path (Join-Path $root "evidence\cases") ($CaseId -replace '[^\w\-.]', '_')
            foreach ($sub in @("02_Original_Extraction", "03_Working_Copy", "05_Exports", "07_Logs", "08_Hashes")) {
                _Add-SafeAcquirePath $candidates (Join-Path (Join-Path $caseRoot $sub) $safeName)
            }
        }
    }

    foreach ($p in @($candidates | Select-Object -Unique)) {
        if (-not $p) { continue }
        $leaf = Split-Path -Leaf $p
        $allow = $false
        if ($RunName -and ($leaf -eq $RunName -or $p -match [regex]::Escape($RunName))) { $allow = $true }
        if ($JobId -and ($leaf -eq $JobId -or $p -match [regex]::Escape($JobId))) { $allow = $true }
        if ($p -match '[\\/]ib[\\/][0-9A-Fa-f]{6,}') { $allow = $true }
        if ($leaf -match '^(02_|03_|05_|07_|08_|CASE-)') { $allow = $false }
        if (-not $allow) { continue }
        try {
            if (Test-Path -LiteralPath $p) {
                cmd.exe /c "rmdir /s /q `"$p`"" | Out-Null
                if (Test-Path -LiteralPath $p) {
                    Remove-Item -LiteralPath $p -Recurse -Force -ErrorAction SilentlyContinue
                }
            }
            if (-not (Test-Path -LiteralPath $p)) { $removed.Add($p) | Out-Null }
        } catch {}
    }

    if ($JobId) {
        foreach ($pat in @(
            (Join-Path $env:TEMP ("acq_ios_" + $JobId + ".*")),
            (Join-Path $env:TEMP ("acq_mtp_" + $JobId + ".*")),
            (Join-Path $env:TEMP ("acq_result_" + $JobId + ".*")),
            (Join-Path $env:TEMP ("acq_progress_" + $JobId + ".*"))
        )) {
            Get-Item -Path $pat -ErrorAction SilentlyContinue | ForEach-Object {
                Remove-Item -LiteralPath $_.FullName -Force -ErrorAction SilentlyContinue
            }
        }
        if (Test-Path -LiteralPath $sidecar) {
            Remove-Item -LiteralPath $sidecar -Force -ErrorAction SilentlyContinue
        }
    }
    if ($progFile) {
        Remove-Item -LiteralPath $progFile -Force -ErrorAction SilentlyContinue
        Remove-Item -LiteralPath ($progFile + ".cancel") -Force -ErrorAction SilentlyContinue
    }
    if ($resultFile) { Remove-Item -LiteralPath $resultFile -Force -ErrorAction SilentlyContinue }
    if ($JobId -and $script:AcquireJobs.ContainsKey($JobId)) { $script:AcquireJobs.Remove($JobId) }

    return @{
        ok        = $true
        cancelled = $stop.cancelled
        removed   = @($removed)
        message   = "Collection stopped and this run's files were removed"
    }
}

function Get-SidecarRunningJobIds {
    $ids = New-Object System.Collections.Generic.List[string]
    $jobsDir = Join-Path $env:TEMP "aetheris_acq_jobs"
    if (-not (Test-Path -LiteralPath $jobsDir)) { return @() }
    foreach ($f in @(Get-ChildItem -LiteralPath $jobsDir -Filter "*.json" -ErrorAction SilentlyContinue)) {
        try {
            $meta = Get-Content -LiteralPath $f.FullName -Raw -Encoding UTF8 | ConvertFrom-Json
            $sid = [int]($(if ($meta.pid) { $meta.pid } else { 0 }))
            if ($sid -le 0) { continue }
            $rf = [string]$meta.result_file
            if ($rf -and (Test-Path -LiteralPath $rf)) {
                $head = ""
                try { $head = Get-Content -LiteralPath $rf -TotalCount 8 -Raw -ErrorAction SilentlyContinue } catch {}
                if ($head -and $head -match '"ok"' -and $head -notmatch '"stage_reached"\s*:\s*"acquire"') { continue }
            }
            $prog = [string]$meta.progress_file
            if ($prog -and ((Test-Path -LiteralPath ($prog + ".cancel")) -or (Test-Path -LiteralPath $prog))) {
                if (Test-Path -LiteralPath ($prog + ".cancel")) { continue }
                try {
                    $pj = Get-Content -LiteralPath $prog -Raw -ErrorAction SilentlyContinue
                    if ($pj -and $pj -match '"stage"\s*:\s*"cancelled"') { continue }
                } catch {}
            }
            if (Get-Process -Id $sid -ErrorAction SilentlyContinue) {
                $ids.Add($f.BaseName) | Out-Null
            }
        } catch {}
    }
    return @($ids)
}

function Get-RunningUsbJobIds {
    $ids = New-Object System.Collections.Generic.List[string]
    foreach ($id in @($script:AcquireJobs.Keys)) {
        $job = $script:AcquireJobs[$id]
        if ($job.Status -ne "running") { continue }
        if ($job.Pid) {
            $proc = Get-Process -Id ([int]$job.Pid) -ErrorAction SilentlyContinue
            if ($proc) { $ids.Add($id) | Out-Null }
        }
    }
    foreach ($sid in @(Get-SidecarRunningJobIds)) {
        if (-not $ids.Contains($sid)) { $ids.Add($sid) | Out-Null }
    }
    return @($ids)
}

function Write-UsbBusyResponse {
    param($Response)
    Write-JsonResponse -Response $Response -StatusCode 409 -Body @{
        ok              = $false
        error           = "Another USB collection is already running. Stop it, wait for it to finish, or register an existing backup folder for forensic analysis."
        busy            = $true
        running_job_ids = @(Get-RunningUsbJobIds)
    }
}

function Test-UsbAcquireInProgress {
    # True only when an async USB acquire process is still alive.
    # The HTTP listener is single-threaded, so a sync /acquire cannot overlap
    # another request. Drive-mount refresh must not block forensic browse,
    # folder register, or a new job on the same phone after a failed acquire.
    $alive = $false
    foreach ($id in @($script:AcquireJobs.Keys)) {
        $job = $script:AcquireJobs[$id]
        if ($job.Status -ne "running") { continue }
        if ($job.Pid) {
            $proc = Get-Process -Id ([int]$job.Pid) -ErrorAction SilentlyContinue
            if ($proc) { $alive = $true; continue }
        }
        Get-AcquireJobStatus -JobId $id | Out-Null
    }
    if (-not $alive) {
        $sidecar = @(Get-SidecarRunningJobIds)
        if ($sidecar.Count -gt 0) { $alive = $true }
    }
    if (-not $alive) {
        $script:AcquireBusy = $false
        $refreshAlive = $false
        if ($script:RefreshProcess) {
            try { $refreshAlive = -not $script:RefreshProcess.HasExited } catch { $refreshAlive = $false }
        }
        if (-not $refreshAlive) { $script:Busy = $false }
    }
    return $alive
}

function Get-AcquireJobStatus {
    param([string]$JobId)

    if (-not $JobId -or -not $script:AcquireJobs.ContainsKey($JobId)) {
        return @{ ok = $false; status = "not_found"; job_id = $JobId; error = "Unknown job id" }
    }
    $job = $script:AcquireJobs[$JobId]
    $alive = $false
    if ($job.Pid) {
        $proc = Get-Process -Id ([int]$job.Pid) -ErrorAction SilentlyContinue
        if ($proc) { $alive = $true }
    }
    if (-not $alive -and $job.Status -in @("cancelled", "completed", "failed")) {
        return @{
            ok      = ($job.Status -ne "failed")
            status  = $job.Status
            job_id  = $JobId
            result  = @{
                ok            = ($job.Status -eq "completed")
                error         = $(if ($job.Status -eq "cancelled") { "Cancelled by examiner" } else { $job.Error })
                errors        = @($(if ($job.Status -eq "cancelled") { "Cancelled by examiner" } else { $job.Error }))
                stage_reached = $job.Status
                paths         = @{}
            }
        }
    }
    if ((Test-Path -LiteralPath $job.ResultFile) -and (-not $alive)) {
        $job.Status = "completed"
        $peekOk = $true
        $runName = ""
        try {
            $fs = [System.IO.File]::OpenRead($job.ResultFile)
            try {
                $buf = New-Object byte[] 2048
                $n = $fs.Read($buf, 0, $buf.Length)
                $head = [System.Text.Encoding]::UTF8.GetString($buf, 0, $n)
                if ($head -match '"ok"\s*:\s*false') { $peekOk = $false; $job.Status = "failed" }
                if ($head -match '"run_name"\s*:\s*"([^"]+)"') { $runName = $Matches[1] }
            } finally { $fs.Close() }
        } catch {}
        $script:AcquireJobs[$JobId] = $job
        $script:Busy = $false
        $script:AcquireBusy = $false
        return @{
            ok          = $true
            status      = $job.Status
            job_id      = $JobId
            result_file = $job.ResultFile
            result      = @{
                ok            = $peekOk
                run_name      = $runName
                stage_reached = $job.Status
            }
        }
    }
    if (-not $alive -and $job.Status -eq "running") {
        $errText = ""
        if ($job.ErrFile -and (Test-Path -LiteralPath $job.ErrFile)) {
            $errText = Get-Content -LiteralPath $job.ErrFile -Raw -EA SilentlyContinue
        }
        $job.Status = "failed"
        $job.Error = if ($errText) { $errText.Trim().Substring(0, [Math]::Min(500, $errText.Trim().Length)) } else { "Acquire process exited without result" }
        $script:AcquireJobs[$JobId] = $job
        $script:Busy = $false
        $script:AcquireBusy = $false
        return @{
            ok     = $false
            status = "failed"
            job_id = $JobId
            error  = $job.Error
            result = @{
                ok            = $false
                error         = $job.Error
                errors        = @($job.Error)
                stage_reached = "failed"
                paths         = @{}
            }
        }
    }
    $detail = ""
    $runName = ""
    $files = 0
    $bytes = [int64]0
    $pct = $null
    if ($job.ProgressFile -and (Test-Path -LiteralPath $job.ProgressFile)) {
        try {
            $p = Get-Content -LiteralPath $job.ProgressFile -Raw -Encoding UTF8 | ConvertFrom-Json
            $detail = [string]$p.detail
            $runName = [string]$p.run_name
            $files = [int]$p.files_seen
            $bytes = [int64]$p.bytes_done
            if ($p.progress_pct -ne $null) { $pct = [double]$p.progress_pct }
        } catch {}
    }
    return @{
        ok           = $true
        status       = "running"
        job_id       = $JobId
        busy         = $true
        progress     = $job.ProgressFile
        started      = $job.StartedUtc
        detail       = $detail
        run_name     = $runName
        files_seen   = $files
        bytes_done   = $bytes
        progress_pct = $pct
        result       = @{
            ok            = $false
            run_name      = $runName
            stage_reached = "acquire"
            detail        = $detail
            progress_pct  = $pct
            acquisition_record = @{ output_size = $bytes; file_count = $files }
        }
    }
}

function Test-Authorized {
    param([System.Net.HttpListenerRequest]$Request)

    if (-not $expectedToken) {
        return $true
    }
    $provided = $Request.Headers["X-Host-Helper-Token"]
    return ($provided -eq $expectedToken)
}

function Read-RequestJson {
    param([System.Net.HttpListenerRequest]$Request)

    if (-not $Request.HasEntityBody) {
        return @{}
    }
    $reader = New-Object System.IO.StreamReader($Request.InputStream, $Request.ContentEncoding)
    try {
        $raw = $reader.ReadToEnd()
    }
    finally {
        $reader.Close()
    }
    if (-not $raw) {
        return @{}
    }
    return ($raw | ConvertFrom-Json)
}

function Test-FolderHasSegmentNames {
    param(
        [string]$Folder,
        [string[]]$Names
    )

    foreach ($name in $Names) {
        $candidate = Join-Path $Folder $name
        if (-not (Test-Path -LiteralPath $candidate -PathType Leaf)) {
            return $false
        }
    }
    return $true
}

function Get-SegmentFilenames {
    param([string[]]$Filenames)

    $pattern = '\.(E\d{2}|e\d{2}|001|002|003|004|005|006|007|008|009|dd|raw|aff|aff4|vmdk|vhdx|pas(?:\d+)?|ufd|ufdx|zip)$'
    return @($Filenames | Where-Object { $_ -and ($_ -match $pattern) } | Select-Object -Unique)
}

function Get-RelativeFolderHint {
    param([string[]]$RelativePaths)

    if (-not $RelativePaths -or -not $RelativePaths.Count) {
        return $null
    }

    $dirPaths = @()
    foreach ($rel in $RelativePaths) {
        $parts = ($rel -replace '\\', '/') -split '/' | Where-Object { $_ }
        if ($parts.Count -le 1) {
            $dirPaths += ""
        }
        else {
            $dirPaths += ($parts[0..($parts.Count - 2)] -join '/')
        }
    }

    if (($dirPaths | Select-Object -Unique).Count -eq 1) {
        return $dirPaths[0]
    }
    return $null
}

function Invoke-ListDir {
    param($Path)
    $raw = ("$Path").Trim()
    if (-not $raw) {
        throw "No path specified"
    }
    $norm = $raw -replace '/', '\'
    if (-not (Test-Path -LiteralPath $norm)) {
        throw "Path not found: $norm"
    }
    $item = Get-Item -LiteralPath $norm -Force -ErrorAction Stop
    $folder = if ($item.PSIsContainer) { [string]$item.FullName } else { [string]$item.DirectoryName }
    $entries = @(Get-ChildItem -LiteralPath $folder -Force -ErrorAction SilentlyContinue | Sort-Object -Property Name)
    $files = New-Object System.Collections.Generic.List[hashtable]
    foreach ($e in $entries) {
        $isDir = $false
        try { $isDir = [bool]$e.PSIsContainer } catch { $isDir = $false }
        $size = $null
        if (-not $isDir) {
            try { $size = [int64]$e.Length } catch { $size = $null }
        }
        $files.Add(@{
            name       = [string]$e.Name
            kind       = $(if ($isDir) { "dir" } else { "file" })
            size_bytes = $size
        }) | Out-Null
    }
    return @{
        ok         = $true
        path       = $folder
        count      = $files.Count
        entries    = $files.ToArray()
        error      = $null
    }
}

function Invoke-StageFolder {
    param(
        [string]$Path,
        [string]$JobId
    )
    $raw = ("$Path").Trim()
    if (-not $raw) {
        throw "No path specified"
    }
    $id = ("$JobId").Trim()
    if ($id -notmatch '^[A-Za-z0-9._-]+$') {
        throw "Invalid job_id"
    }
    $norm = $raw -replace '/', '\'
    if (-not (Test-Path -LiteralPath $norm)) {
        throw "Path not found: $norm"
    }
    $item = Get-Item -LiteralPath $norm -Force -ErrorAction Stop
    $src = if ($item.PSIsContainer) { [string]$item.FullName } else { [string]$item.DirectoryName }
    $dest = Join-Path $root "data\uploads\$id\from-path"
    New-Item -ItemType Directory -Force -Path $dest | Out-Null
    & robocopy $src $dest /E /COPY:DAT /R:1 /W:1 /MT:8 /NFL /NDL /NJH /NJS | Out-Null
    $code = $LASTEXITCODE
    if ($code -ge 8) {
        throw "Failed to copy $src to $dest (robocopy $code)"
    }
    return @{
        ok     = $true
        path   = $src
        dest   = $dest
        job_id = $id
        error  = $null
    }
}

function Invoke-ResolveFolder {
    param(
        [string[]]$Filenames,
        [string]$FolderHint = "",
        [string[]]$RelativePaths = @()
    )

    $names = Get-SegmentFilenames $Filenames
    if (-not $names.Count) {
        throw "No disk or mobile segment files (.E01, .pas, .ufd, ...) in the selection"
    }

    # Fast path: absolute Windows path (G:\folder\...) - never scan whole disks.
    $absoluteHints = New-Object System.Collections.Generic.List[string]
    foreach ($raw in (@($FolderHint) + @($RelativePaths))) {
        if (-not $raw) { continue }
        $t = [string]$raw.Trim()
        if ($t -match '^[A-Za-z]:[\\/]') {
            $norm = $t -replace '/', '\'
            if (Test-Path -LiteralPath $norm -PathType Leaf) {
                $norm = Split-Path -LiteralPath $norm -Parent
            }
            if ($norm -and -not $absoluteHints.Contains($norm)) {
                [void]$absoluteHints.Add($norm)
            }
        }
    }
    foreach ($abs in $absoluteHints) {
        if ((Test-Path -LiteralPath $abs -PathType Container) -and (Test-FolderHasSegmentNames $abs $names)) {
            return @{
                ok            = $true
                path          = $abs
                segment_count = $names.Count
                error         = $null
            }
        }
    }

    $hints = New-Object System.Collections.Generic.List[string]
    $relHint = Get-RelativeFolderHint $RelativePaths
    if ($relHint) { [void]$hints.Add(($relHint -replace '/', '\')) }
    if ($FolderHint) {
        $clean = $FolderHint.Trim().Trim('\', '/')
        if ($clean -match '^[A-Za-z]:[\\/]?(.*)$') {
            $clean = $Matches[1]
        }
        if ($clean -and -not $hints.Contains($clean)) {
            [void]$hints.Add($clean)
        }
    }

    $drives = @(Get-WorkstationDriveLetters | ForEach-Object { "${_}:\" })
    if (-not $drives.Count) {
        $drives = @(Get-PSDrive -PSProvider FileSystem |
            Where-Object { $_.Name -match '^[A-Z]$' } |
            ForEach-Object { "$($_.Name):\" })
    }

    # Prefer exact Join-Path candidates only (no deep recurse).
    foreach ($hint in $hints) {
        if (-not $hint) { continue }
        $hintParts = @($hint -split '[\\/]' | Where-Object { $_ })
        foreach ($drive in $drives) {
            $candidates = New-Object System.Collections.Generic.List[string]
            [void]$candidates.Add((Join-Path $drive $hint))
            for ($i = 0; $i -lt [Math]::Min($hintParts.Count, 4); $i++) {
                [void]$candidates.Add((Join-Path $drive ($hintParts[$i..($hintParts.Count - 1)] -join '\')))
            }
            foreach ($candidate in ($candidates | Select-Object -Unique)) {
                if ((Test-Path -LiteralPath $candidate -PathType Container) -and (Test-FolderHasSegmentNames $candidate $names)) {
                    return @{
                        ok            = $true
                        path          = $candidate
                        segment_count = $names.Count
                        error         = $null
                    }
                }
            }
        }
    }

    # Name search on non-system drives (skip C:). Depth 8 covers paths like
    # D:\all\Fotrensics_Data\DISK2\DataExtration\SegerEx-1 (was depth 3 → never found).
    $baseName = $null
    if ($hints.Count) {
        $baseName = Split-Path ($hints[0]) -Leaf
    }
    $searchDepth = 8
    if ($baseName) {
        $searchDrives = @($drives | Where-Object { $_ -notmatch '^[Cc]:' })
        foreach ($drive in $searchDrives) {
            try {
                $matches = Get-ChildItem -LiteralPath $drive -Filter $baseName -Directory -Recurse -Depth $searchDepth -ErrorAction SilentlyContinue |
                    Select-Object -First 40
                foreach ($match in $matches) {
                    if (Test-FolderHasSegmentNames $match.FullName $names) {
                        return @{
                            ok            = $true
                            path          = $match.FullName
                            segment_count = $names.Count
                            error         = $null
                        }
                    }
                }
            }
            catch { }
        }
    }

    # Last resort: look for first segment filename only, non-C: drives.
    $anchor = $names | Select-Object -First 1
    if ($anchor) {
        $searchDrives = @($drives | Where-Object { $_ -notmatch '^[Cc]:' })
        foreach ($drive in $searchDrives) {
            try {
                $hits = Get-ChildItem -LiteralPath $drive -Filter $anchor -File -Recurse -Depth $searchDepth -ErrorAction SilentlyContinue |
                    Select-Object -First 20
                foreach ($hit in $hits) {
                    if (Test-FolderHasSegmentNames $hit.DirectoryName $names) {
                        return @{
                            ok            = $true
                            path          = $hit.DirectoryName
                            segment_count = $names.Count
                            error         = $null
                        }
                    }
                }
            }
            catch { }
        }
    }

    throw "Could not find a workstation folder containing $($names.Count) selected segment file(s). Paste the full path (e.g. G:\folder) and click Register & start."
}

function Get-WorkstationDriveLetters {
    $volumes = Get-WorkstationDriveVolumes
    return @($volumes | ForEach-Object { $_.letter } | Sort-Object -Unique)
}

function Get-ComposeDriveLettersFromFile {
    param([string]$Path)
    $letters = @()
    if (-not $Path -or -not (Test-Path -LiteralPath $Path)) { return @() }
    foreach ($line in @(Get-Content -LiteralPath $Path -ErrorAction SilentlyContinue)) {
        if (("$line") -match 'target:\s*/host/([a-zA-Z])\s*$') {
            $letters += $Matches[1].ToUpper()
        }
    }
    return @($letters | Sort-Object -Unique)
}

function Start-DrivePresenceWatcher {
    # Any newly attached letter (USB / extra forensic disk) must be composed
    # into /host/<letter> immediately so folder pick + extraction can start.
    $forensicYml = Join-Path $root "docker-compose.drives.forensic.yml"
    $script:LastSeenDriveKey = ((Get-WorkstationDriveLetters) -join ',')
    $ymlKey = ((Get-ComposeDriveLettersFromFile $forensicYml) -join ',')
    if ($script:LastSeenDriveKey -and $ymlKey -and $script:LastSeenDriveKey -ne $ymlKey) {
        Write-Host "Drive letters on this PC ($($script:LastSeenDriveKey)) differ from Docker mounts ($ymlKey). Refreshing now."
        try { Start-RefreshDriveMountsAsync | Out-Null } catch {
            Write-Host "Startup drive remount skipped: $($_.Exception.Message)"
        }
    }

    $timer = New-Object System.Timers.Timer
    $timer.Interval = 8000
    $timer.AutoReset = $true
    $null = Register-ObjectEvent -InputObject $timer -EventName Elapsed -SourceIdentifier "AetherisDriveWatch" -MessageData @{ Port = $Port; Root = $root } -Action {
        try {
            $port = [int]$Event.MessageData.Port
            $rootPath = [string]$Event.MessageData.Root
            $letters = New-Object System.Collections.Generic.List[string]
            Get-Volume -ErrorAction SilentlyContinue |
                Where-Object { $_.DriveLetter -and "$($_.DriveLetter)" -match '^[A-Z]$' } |
                ForEach-Object { [void]$letters.Add("$($_.DriveLetter)".ToUpper()) }
            Get-Partition -ErrorAction SilentlyContinue |
                Where-Object { $_.DriveLetter -and "$($_.DriveLetter)" -match '^[A-Z]$' } |
                ForEach-Object { [void]$letters.Add("$($_.DriveLetter)".ToUpper()) }
            Get-CimInstance Win32_LogicalDisk -ErrorAction SilentlyContinue |
                Where-Object { $_.DeviceID -match '^[A-Z]:$' } |
                ForEach-Object { [void]$letters.Add($_.DeviceID.Substring(0, 1).ToUpper()) }
            foreach ($code in 65..90) {
                $L = [string][char]$code
                if ($letters -contains $L) { continue }
                if (Test-Path -LiteralPath "${L}:\") { [void]$letters.Add($L) }
            }
            $key = (($letters | Sort-Object -Unique) -join ',')
            $stateDir = Join-Path $env:LOCALAPPDATA "Aetheris"
            if (-not (Test-Path -LiteralPath $stateDir)) {
                New-Item -ItemType Directory -Path $stateDir -Force | Out-Null
            }
            $stateFile = Join-Path $stateDir "helper-drive-letters.txt"
            $prev = if (Test-Path -LiteralPath $stateFile) { (Get-Content -LiteralPath $stateFile -Raw).Trim() } else { '' }
            $ymlFile = Join-Path $rootPath "docker-compose.drives.forensic.yml"
            if (-not (Test-Path -LiteralPath $ymlFile)) { $ymlFile = Join-Path $rootPath "docker-compose.drives.generated.yml" }
            $ymlLetters = New-Object System.Collections.Generic.List[string]
            if (Test-Path -LiteralPath $ymlFile) {
                foreach ($line in @(Get-Content -LiteralPath $ymlFile -ErrorAction SilentlyContinue)) {
                    if (("$line") -match 'target:\s*/host/([a-zA-Z])\s*$') {
                        [void]$ymlLetters.Add($Matches[1].ToUpper())
                    }
                }
            }
            $ymlKey = (($ymlLetters | Sort-Object -Unique) -join ',')
            $staleMount = $false
            $apiName = ""
            try {
                $apiName = (docker ps --filter "name=aetheris-forensic-api" --format "{{.Names}}" 2>$null | Select-Object -First 1)
            } catch { $apiName = "" }
            if ($apiName -and $letters.Count) {
                foreach ($letter in @($letters | Sort-Object -Unique)) {
                    $low = "$letter".ToLower()
                    $winRoot = "${letter}:\"
                    $winHasFiles = $false
                    try {
                        $winHasFiles = [bool](Get-ChildItem -LiteralPath $winRoot -Force -ErrorAction Stop | Select-Object -First 1)
                    } catch { $winHasFiles = $false }
                    $probe = docker exec $apiName python -c "import os; print(len(os.listdir('/host/$low')))" 2>&1 | Out-String
                    if ($LASTEXITCODE -ne 0 -and ($probe -match 'No such device|ENODEV|Errno 19')) {
                        $staleMount = $true
                        break
                    }
                    if ($winHasFiles -and $LASTEXITCODE -eq 0 -and ($probe.Trim() -eq '0')) {
                        $staleMount = $true
                        break
                    }
                }
            }
            if ($staleMount) {
                $resolve = Join-Path $rootPath "scripts\resolve-docker-drive-source.ps1"
                if (Test-Path -LiteralPath $resolve) {
                    foreach ($letter in @($letters | Sort-Object -Unique)) {
                        $winHas = $false
                        try {
                            $winHas = [bool](Get-ChildItem -LiteralPath "${letter}:\" -Force -ErrorAction Stop | Select-Object -First 1)
                        } catch { $winHas = $false }
                        if (-not $winHas) { continue }
                        & powershell.exe -NoProfile -ExecutionPolicy Bypass -File $resolve -DriveLetter $letter -RemountOnly | Out-Null
                    }
                    $stillEmpty = $false
                    if ($apiName) {
                        foreach ($letter in @($letters | Sort-Object -Unique)) {
                            $low = "$letter".ToLower()
                            $winHas = $false
                            try {
                                $winHas = [bool](Get-ChildItem -LiteralPath "${letter}:\" -Force -ErrorAction Stop | Select-Object -First 1)
                            } catch { $winHas = $false }
                            if (-not $winHas) { continue }
                            $probe2 = docker exec $apiName python -c "import os; print(len(os.listdir('/host/$low')))" 2>&1 | Out-String
                            if ($LASTEXITCODE -ne 0 -or ($probe2.Trim() -eq '0')) {
                                $stillEmpty = $true
                                break
                            }
                        }
                    }
                    else {
                        $stillEmpty = $true
                    }
                    if (-not $stillEmpty) { $staleMount = $false }
                }
            }
            if ($key -and (($prev -ne $key) -or ($ymlKey -and $ymlKey -ne $key) -or $staleMount)) {
                Invoke-RestMethod -Method POST -Uri "http://127.0.0.1:$port/refresh-drive-mounts" -ContentType "application/json" -Body '{}' -TimeoutSec 8 | Out-Null
            }
            Set-Content -LiteralPath $stateFile -Value $key -Encoding UTF8
        }
        catch { }
    }
    $timer.Enabled = $true
    $script:DriveWatchTimer = $timer
}

function Resolve-MobileOsHint {
    param(
        [string]$FriendlyName = "",
        [string]$InstanceId = ""
    )
    $blob = "$FriendlyName $InstanceId"
    if ($blob -match '(?i)VID_05AC|iPhone|iPad|iPod|Apple Mobile Device|Apple iPad') {
        return "ios"
    }
    # Google, Samsung, Xiaomi, Huawei, OnePlus, HTC, Motorola, MediaTek, Oppo, Vivo,
    # ZTE, Alcatel, Qualcomm (many cheap/old Androids), Sony, LG, Asus, Lenovo, Zebra.
    $androidVid = '(?i)VID_(18D1|04E8|2717|2A45|2A47|0BB4|22B8|12D1|2A70|0E8D|19D2|22D9|29A9|1BBB|05C6|0A9D|2B4C|0FCE|1004|0B05|17EF|0E79|2D95)'
    $androidName = '(?i)Android|Samsung|Galaxy|Xiaomi|Redmi|POCO|Huawei|Honor|OnePlus|Pixel|Motorola|Moto|Nokia|Oppo|Vivo|Realme|Tecno|Infinix|Itel|Nothing|Asus|Sony|Xperia|LG |Lenovo|ZTE|Alcatel|TCL|Meizu|Fairphone|Blackview|Umidigi|Doogee|Lava|Micromax|MTP'
    if ($blob -match $androidVid -or $blob -match $androidName) {
        return "android"
    }
    return "other"
}

function Get-IosBackupRoots {
    $candidates = @(
        (Join-Path $env:USERPROFILE "Apple\MobileSync\Backup"),
        (Join-Path $env:APPDATA "Apple Computer\MobileSync\Backup"),
        (Join-Path $env:USERPROFILE "AppData\Roaming\Apple Computer\MobileSync\Backup")
    )
    $roots = @()
    foreach ($path in $candidates) {
        if ($path -and (Test-Path -LiteralPath $path -PathType Container)) {
            $roots += $path
        }
    }
    return @($roots | Select-Object -Unique)
}


function Get-PnpClassSafe {
    param([string]$Class, [int]$TimeoutSec = 4)
    # Get-PnpDevice can hang forever on a wedged phone USB stack. Bound it.
    try {
        $job = Start-Job -ScriptBlock {
            param($c)
            @(Get-PnpDevice -PresentOnly -Class $c -ErrorAction SilentlyContinue |
                Where-Object { $_.Status -eq "OK" } |
                ForEach-Object {
                    [pscustomobject]@{
                        FriendlyName = [string]$_.FriendlyName
                        Class        = [string]$_.Class
                        InstanceId   = [string]$_.InstanceId
                    }
                })
        } -ArgumentList $Class
        if (Wait-Job $job -Timeout $TimeoutSec) {
            $rows = @(Receive-Job $job)
            Remove-Job $job -Force -ErrorAction SilentlyContinue
            return $rows
        }
        Stop-Job $job -ErrorAction SilentlyContinue
        Remove-Job $job -Force -ErrorAction SilentlyContinue
        return @()
    }
    catch {
        return @()
    }
}

function Get-PcscSimStatus {
    $readers = New-Object System.Collections.Generic.List[string]
    $winscard = Join-Path $env:SystemRoot "System32\winscard.dll"
    $svc = Get-Service -Name "SCardSvr" -ErrorAction SilentlyContinue
    if (-not (Test-Path -LiteralPath $winscard) -and $null -eq $svc) {
        return @{ available = $false; readers = @(); reason = "Windows PC/SC (winscard / SCardSvr) is not present on this PC" }
    }
    if ($null -ne $svc -and $svc.Status -ne "Running") {
        try { Start-Service -Name "SCardSvr" -ErrorAction Stop } catch {}
        try { $svc.Refresh() } catch {}
    }
    # Do not call Get-PnpDevice — it can hang the helper request queue.
    $svcRunning = $null -ne $svc -and $svc.Status -eq "Running"
    if ($readers.Count -gt 0) { $reason = "PC/SC ready on examiner host ($($readers.Count) reader(s))" }
    elseif ($svcRunning) { $reason = "PC/SC (SCardSvr) ready - plug in a SIM/USIM reader to detect cards" }
    else { $reason = "PC/SC tooling present (winscard). Start SCardSvr and attach a SIM reader." }
    return @{ available = $true; readers = @($readers); reason = $reason }
}
function Get-StartedUsbInstanceIds {
    $ids = New-Object 'System.Collections.Generic.HashSet[string]' ([StringComparer]::OrdinalIgnoreCase)
    $tmp = Join-Path $env:TEMP ("aetheris_pnputil_" + [guid]::NewGuid().ToString("N") + ".txt")
    $err = $tmp + ".err"
    $pnputil = Join-Path $env:SystemRoot "System32\pnputil.exe"
    $pnputilOk = $false
    try {
        if (Test-Path -LiteralPath $pnputil) {
            $proc = Start-Process -FilePath $pnputil -ArgumentList @("/enum-devices", "/connected", "/ids") `
                -PassThru -WindowStyle Hidden -RedirectStandardOutput $tmp -RedirectStandardError $err
            if (-not $proc.WaitForExit(5000)) {
                try { $proc.Kill() } catch {}
            } else {
                $pnputilOk = ($proc.ExitCode -eq 0)
            }
            if (Test-Path -LiteralPath $tmp) {
                foreach ($line in @(Get-Content -LiteralPath $tmp -ErrorAction SilentlyContinue)) {
                    if ($line -match '(?i)Instance ID:\s+(\S+)') {
                        $id = [string]$Matches[1]
                        if ($id -match '(?i)USB\\VID_') { [void]$ids.Add($id) }
                    }
                }
                $pnputilOk = $true
            }
        }
    } catch {}
    finally {
        Remove-Item -LiteralPath $tmp, $err -Force -ErrorAction SilentlyContinue
    }
    if ($pnputilOk) { return $ids }
    $svcRoot = "HKLM:\SYSTEM\CurrentControlSet\Services"
    try {
        Get-ChildItem -LiteralPath $svcRoot -ErrorAction SilentlyContinue | ForEach-Object {
            $enumPath = Join-Path $_.PSPath "Enum"
            if (-not (Test-Path -LiteralPath $enumPath)) { return }
            $enum = Get-ItemProperty -LiteralPath $enumPath -ErrorAction SilentlyContinue
            if (-not $enum) { return }
            $count = 0
            try { $count = [int]$enum.Count } catch { $count = 0 }
            if ($count -le 0) { return }
            for ($i = 0; $i -lt $count; $i++) {
                $id = [string]$enum."$i"
                if ($id -match '(?i)USB\\VID_') { [void]$ids.Add($id) }
            }
        }
    } catch {}
    return $ids
}

function Test-WpdIdCurrentlyAttached {
    param([string]$WpdId, $StartedIds)
    if (-not $WpdId -or $null -eq $StartedIds) { return $false }
    $norm = ($WpdId -replace '#', '\' -replace '/', '\').ToUpperInvariant()
    $vid = $null; $prodId = $null; $serial = $null
    if ($norm -match 'VID_([0-9A-F]{4})') { $vid = $Matches[1] }
    if ($norm -match 'PID_([0-9A-F]{4})') { $prodId = $Matches[1] }
    if ($norm -match 'VID_[0-9A-F]{4}&PID_[0-9A-F]{4}[^\\]*\\([^\\&]+)') { $serial = $Matches[1] }
    if (-not $vid -or -not $prodId) { return $false }
    foreach ($started in $StartedIds) {
        $s = ([string]$started).ToUpperInvariant()
        if ($s -notmatch ("VID_" + $vid) -or $s -notmatch ("PID_" + $prodId)) { continue }
        if ($serial -and $s -match [regex]::Escape($serial)) { return $true }
        if (-not $serial) { return $true }
    }
    return $false
}

function Get-PresentWpdPhones {
    $started = Get-StartedUsbInstanceIds
    $list = @()
    $seen = @{}
    foreach ($regRoot in @(
        "HKLM:\SOFTWARE\Microsoft\Windows Portable Devices\Devices",
        "HKCU:\SOFTWARE\Microsoft\Windows Portable Devices\Devices"
    )) {
        if (-not (Test-Path -LiteralPath $regRoot)) { continue }
        Get-ChildItem -LiteralPath $regRoot -ErrorAction SilentlyContinue | ForEach-Object {
            $props = Get-ItemProperty -LiteralPath $_.PSPath -ErrorAction SilentlyContinue
            $name = [string]$props.FriendlyName
            $id = [string]$_.PSChildName
            if (-not $name) { $name = $id }
            if (-not $id) { return }
            if ($name -match '(?i)^(Local Disk|Windows|Network|CD Drive|DVD|Removable Disk|New Volume|CCCOMA_|RUFUS_)') { return }
            $looksPhone = ($name -match '(?i)iPhone|iPad|iPod|Apple|Android|Samsung|Galaxy|Xiaomi|Redmi|Huawei|Honor|OnePlus|Pixel|Oppo|Vivo|Tecno|Infinix|Motorola|Nokia|Realme|Nothing|Phone') -or
                ($id -match '(?i)VID_(05AC|18D1|04E8|2717|2A45|0E8D|2A70|19D2|22D9|29A9|05C6|12D1|22B8|0BB4|0FCE|1004|0B05|2B4C|2D95)')
            if (-not $looksPhone) { return }
            if (-not (Test-WpdIdCurrentlyAttached -WpdId $id -StartedIds $started)) { return }
            $os = "android"
            if ($name -match '(?i)iPhone|iPad|iPod|Apple' -or $id -match '(?i)VID_05AC') { $os = "ios" }
            $key = ($name + "|" + $os).ToLowerInvariant()
            if ($id -match 'VID_([0-9A-Fa-f]{4}).*?PID_([0-9A-Fa-f]{4})') {
                $key = $os + "|" + $Matches[1].ToUpperInvariant() + "|" + $Matches[2].ToUpperInvariant()
            }
            if ($seen.ContainsKey($key)) { return }
            $seen[$key] = $true
            $list += @{
                id               = $id
                name             = $name
                device_class     = "WPD"
                connection       = "mtp"
                os_hint          = $os
                instance_id      = $id
                has_drive_letter = $false
                live_acquire     = $true
                capability_label = "SUPPORTED_DIRECT_LOGICAL"
                guidance         = "Connected phone detected. Use Start extraction."
                ios_backup_roots = @()
            }
        }
    }
    return $list
}

function Write-MobileDeviceCaches {
    $list = @(Get-PresentWpdPhones)
    $json = if ($list.Count -eq 0) { "[]" } elseif ($list.Count -eq 1) { "[" + ($list[0] | ConvertTo-Json -Compress -Depth 6) + "]" } else { ($list | ConvertTo-Json -Compress -Depth 6) }
    [System.IO.File]::WriteAllText($script:DeviceCacheFile, $json)
    $acq = @()
    foreach ($d in $list) {
        $os = [string]$d.os_hint
        $acq += @{
            adapter     = $(if ($os -eq "ios") { "ios_lockdown" } else { "android_mtp" })
            device_id   = [string]$d.id
            label       = [string]$d.name
            status      = "wpd"
            os_family   = $(if ($os) { $os } else { "android" })
            instance_id = [string]$d.instance_id
            connection  = [string]$d.connection
        }
    }
    $acqBody = @{ ok = $true; devices = $acq; warnings = @(); count = $acq.Count }
    [System.IO.File]::WriteAllText($script:AcqDevicesCacheFile, ($acqBody | ConvertTo-Json -Compress -Depth 6))
    $script:DeviceCache = $list
    $script:DeviceCacheAt = Get-Date
}

function Read-MobileDeviceCacheFile {
    $file = $script:DeviceCacheFile
    if (-not $file -or -not (Test-Path -LiteralPath $file)) { return @($script:DeviceCache) }
    try {
        $raw = Get-Content -LiteralPath $file -Raw -ErrorAction Stop
        if (-not $raw) { return @($script:DeviceCache) }
        $obj = $raw | ConvertFrom-Json
        if ($null -eq $obj) { return @($script:DeviceCache) }
        $rows = @($obj)
        $script:DeviceCache = $rows
        $script:DeviceCacheAt = Get-Date
        return $rows
    } catch {
        return @($script:DeviceCache)
    }
}

function Start-MobileDeviceRefresh {
    if ($script:DeviceRefreshJob -and $script:DeviceRefreshJob.State -eq "Running") { return }
    try {
        if ($script:DeviceRefreshJob) {
            Remove-Job $script:DeviceRefreshJob -Force -ErrorAction SilentlyContinue
        }
    } catch {}
    $script:DeviceRefreshJob = Start-Job -Name "aetheris-mobile-refresh" -ScriptBlock {
        param($CacheFile, $AcqFile)
        function Get-StartedUsbInstanceIds {
            $ids = New-Object 'System.Collections.Generic.HashSet[string]' ([StringComparer]::OrdinalIgnoreCase)
            $tmp = Join-Path $env:TEMP ("aetheris_pnputil_" + [guid]::NewGuid().ToString("N") + ".txt")
            $err = $tmp + ".err"
            $pnputil = Join-Path $env:SystemRoot "System32\pnputil.exe"
            $pnputilOk = $false
            try {
                if (Test-Path -LiteralPath $pnputil) {
                    $proc = Start-Process -FilePath $pnputil -ArgumentList @("/enum-devices", "/connected", "/ids") `
                        -PassThru -WindowStyle Hidden -RedirectStandardOutput $tmp -RedirectStandardError $err
                    if (-not $proc.WaitForExit(5000)) { try { $proc.Kill() } catch {} }
                    if (Test-Path -LiteralPath $tmp) {
                        foreach ($line in @(Get-Content -LiteralPath $tmp -ErrorAction SilentlyContinue)) {
                            if ($line -match '(?i)Instance ID:\s+(\S+)') {
                                $id = [string]$Matches[1]
                                if ($id -match '(?i)USB\\VID_') { [void]$ids.Add($id) }
                            }
                        }
                        $pnputilOk = $true
                    }
                }
            } catch {}
            finally { Remove-Item -LiteralPath $tmp, $err -Force -ErrorAction SilentlyContinue }
            if ($pnputilOk) { return $ids }
            Get-ChildItem -LiteralPath "HKLM:\SYSTEM\CurrentControlSet\Services" -ErrorAction SilentlyContinue | ForEach-Object {
                $enumPath = Join-Path $_.PSPath "Enum"
                if (-not (Test-Path -LiteralPath $enumPath)) { return }
                $enum = Get-ItemProperty -LiteralPath $enumPath -ErrorAction SilentlyContinue
                if (-not $enum) { return }
                $count = 0
                try { $count = [int]$enum.Count } catch { $count = 0 }
                for ($i = 0; $i -lt $count; $i++) {
                    $id = [string]$enum."$i"
                    if ($id -match '(?i)USB\\VID_') { [void]$ids.Add($id) }
                }
            }
            return $ids
        }
        function Test-WpdIdCurrentlyAttached {
            param([string]$WpdId, $StartedIds)
            if (-not $WpdId -or $null -eq $StartedIds) { return $false }
            $norm = ($WpdId -replace '#', '\').ToUpperInvariant()
            $vid = $null; $prodId = $null; $serial = $null
            if ($norm -match 'VID_([0-9A-F]{4})') { $vid = $Matches[1] }
            if ($norm -match 'PID_([0-9A-F]{4})') { $prodId = $Matches[1] }
            if ($norm -match 'VID_[0-9A-F]{4}&PID_[0-9A-F]{4}[^\\]*\\([^\\&]+)') { $serial = $Matches[1] }
            if (-not $vid -or -not $prodId) { return $false }
            foreach ($started in $StartedIds) {
                $s = ([string]$started).ToUpperInvariant()
                if ($s -notmatch ("VID_" + $vid) -or $s -notmatch ("PID_" + $prodId)) { continue }
                if ($serial -and $s -match [regex]::Escape($serial)) { return $true }
                if (-not $serial) { return $true }
            }
            return $false
        }
        function Read-WpdPhones {
            $started = Get-StartedUsbInstanceIds
            $list = @()
            $seen = @{}
            foreach ($regRoot in @(
                "HKLM:\SOFTWARE\Microsoft\Windows Portable Devices\Devices",
                "HKCU:\SOFTWARE\Microsoft\Windows Portable Devices\Devices"
            )) {
                if (-not (Test-Path -LiteralPath $regRoot)) { continue }
                Get-ChildItem -LiteralPath $regRoot -ErrorAction SilentlyContinue | ForEach-Object {
                    $props = Get-ItemProperty -LiteralPath $_.PSPath -ErrorAction SilentlyContinue
                    $name = [string]$props.FriendlyName
                    $id = [string]$_.PSChildName
                    if (-not $name) { $name = $id }
                    if (-not $id) { return }
                    if ($name -match '(?i)^(Local Disk|Windows|Network|CD Drive|DVD|Removable Disk|New Volume|CCCOMA_|RUFUS_)') { return }
                    $looksPhone = ($name -match '(?i)iPhone|iPad|iPod|Apple|Android|Samsung|Galaxy|Xiaomi|Redmi|Huawei|Honor|OnePlus|Pixel|Oppo|Vivo|Tecno|Infinix|Motorola|Nokia|Realme|Nothing|Phone') -or
                        ($id -match '(?i)VID_(05AC|18D1|04E8|2717|2A45|0E8D|2A70|19D2|22D9|29A9|05C6|12D1|22B8|0BB4|0FCE|1004|0B05|2B4C|2D95)')
                    if (-not $looksPhone) { return }
                    if (-not (Test-WpdIdCurrentlyAttached -WpdId $id -StartedIds $started)) { return }
                    $os = "android"
                    if ($name -match '(?i)iPhone|iPad|iPod|Apple' -or $id -match '(?i)VID_05AC') { $os = "ios" }
                    $key = ($name + "|" + $os).ToLowerInvariant()
                    if ($id -match 'VID_([0-9A-Fa-f]{4}).*?PID_([0-9A-Fa-f]{4})') {
                        $key = $os + "|" + $Matches[1].ToUpperInvariant() + "|" + $Matches[2].ToUpperInvariant()
                    }
                    if ($seen.ContainsKey($key)) { return }
                    $seen[$key] = $true
                    $list += @{
                        id               = $id
                        name             = $name
                        device_class     = "WPD"
                        connection       = "mtp"
                        os_hint          = $os
                        instance_id      = $id
                        has_drive_letter = $false
                        live_acquire     = $true
                        capability_label = "SUPPORTED_DIRECT_LOGICAL"
                        guidance         = "Connected phone detected. Use Start extraction."
                        ios_backup_roots = @()
                    }
                }
            }
            return $list
        }
        while ($true) {
            try {
                $list = @(Read-WpdPhones)
                $json = if ($list.Count -eq 0) { "[]" } elseif ($list.Count -eq 1) { "[" + ($list[0] | ConvertTo-Json -Compress -Depth 6) + "]" } else { ($list | ConvertTo-Json -Compress -Depth 6) }
                [System.IO.File]::WriteAllText($CacheFile, $json)
                $acq = @()
                foreach ($d in $list) {
                    $os = [string]$d.os_hint
                    $acq += @{
                        adapter     = $(if ($os -eq "ios") { "ios_lockdown" } else { "android_mtp" })
                        device_id   = [string]$d.id
                        label       = [string]$d.name
                        status      = "wpd"
                        os_family   = $(if ($os) { $os } else { "android" })
                        instance_id = [string]$d.instance_id
                        connection  = [string]$d.connection
                    }
                }
                $acqBody = @{ ok = $true; devices = $acq; warnings = @(); count = $acq.Count }
                [System.IO.File]::WriteAllText($AcqFile, ($acqBody | ConvertTo-Json -Compress -Depth 6))
            } catch {}
            Start-Sleep -Seconds 6
        }
    } -ArgumentList $script:DeviceCacheFile, $script:AcqDevicesCacheFile
}

function Write-HostAdapterCache {
    $body = @{
        ok = $true
        adapters = @(
            @{ name = "android_adb"; os_family = "android"; available = $true; reason = "Host USB helper (USB debugging when authorised)"; via = "host" }
            @{ name = "android_mtp"; os_family = "android"; available = $true; reason = "Windows MTP/WPD ready (file transfer, no USB debugging)"; via = "host" }
            @{ name = "ios_lockdown"; os_family = "ios"; available = $true; reason = "Host USB helper (unlock and Trust This Computer)"; via = "host" }
            @{ name = "sim_reader"; os_family = "sim"; available = $true; reason = "PC/SC on the examiner host"; via = "host" }
            @{ name = "removable_media"; os_family = "storage"; available = $true; reason = "Host removable volumes via /drives"; via = "host" }
        )
    }
    [System.IO.File]::WriteAllText($script:AdaptersCacheFile, ($body | ConvertTo-Json -Compress -Depth 6))
}

function Get-ConnectedMobileDevices {
    return @(Read-MobileDeviceCacheFile)
}

function Get-ConnectedMobileDevices-LegacyUnused {
    $devices = New-Object System.Collections.Generic.List[object]
    $seen = New-Object 'System.Collections.Generic.HashSet[string]' ([StringComparer]::OrdinalIgnoreCase)
    $backupRoots = @(Get-IosBackupRoots)
    try {

    function Add-MobileDevice {
        param(
            [string]$Id,
            [string]$Name,
            [string]$DeviceClass = "",
            [string]$Connection = "usb",
            [string]$OsHint = "other",
            [string]$InstanceId = ""
        )
        if (-not $Id -or -not $Name) { return }
        if (-not $seen.Add($Id)) { return }
        # Prefer the friendly WPD name over composite USB entries with the same serial.
        $devices.Add(@{
            id               = $Id
            name             = $Name
            device_class     = $DeviceClass
            connection       = $Connection
            os_hint          = $OsHint
            instance_id      = $InstanceId
            has_drive_letter = $false
            live_acquire     = $true
            capability_label = "SUPPORTED_DIRECT_LOGICAL"
            guidance         = "Connected phone detected. Use Start extraction to create a logical image package under forensic-mobile-acquisitions\{job_id}."
            ios_backup_roots = [string[]]($(if ($OsHint -eq "ios") { @($backupRoots) } else { @() }))
        })
    }

    # Registry only. Shell.Application and Get-PnpDevice can hang for minutes
    # on a wedged MTP stack and would block Identify + Start extraction.
    $phoneVid = '(?i)VID_(05AC|18D1|04E8|2717|2A45|0E8D|2A70|19D2|22D9|29A9|05C6|12D1|22B8|0BB4|0FCE|1004|0B05|2B4C|2A47|04C5|0451|2D95)'
    foreach ($regRoot in @(
        "HKLM:\SOFTWARE\Microsoft\Windows Portable Devices\Devices",
        "HKCU:\SOFTWARE\Microsoft\Windows Portable Devices\Devices"
    )) {
        if (-not (Test-Path -LiteralPath $regRoot)) { continue }
        try {
            Get-ChildItem -LiteralPath $regRoot -ErrorAction SilentlyContinue | ForEach-Object {
                $props = Get-ItemProperty -LiteralPath $_.PSPath -ErrorAction SilentlyContinue
                $name = [string]$props.FriendlyName
                $id = [string]$_.PSChildName
                if (-not $name) { $name = $id }
                if ($name -match '(?i)^(Local Disk|Windows|Network|CD Drive|DVD|Removable Disk)') { return }
                $osHint = Resolve-MobileOsHint -FriendlyName $name -InstanceId $id
                if ($osHint -eq "other" -and $name -notmatch '(?i)iPhone|iPad|Android|Phone|Samsung|Xiaomi|Huawei|Honor|OnePlus|Pixel|Oppo|Vivo|Tecno|Infinix|Portable|Galaxy|Redmi|MTP') {
                    if ($id -notmatch $phoneVid) { return }
                    $osHint = "android"
                }
                Add-MobileDevice -Id $id -Name $name -DeviceClass "WPD" -Connection "mtp" -OsHint $osHint -InstanceId $id
            }
        } catch {}
    }
    $usbRoot = "HKLM:\SYSTEM\CurrentControlSet\Enum\USB"
    if (Test-Path -LiteralPath $usbRoot) {
        try {
            Get-ChildItem -LiteralPath $usbRoot -ErrorAction SilentlyContinue |
                Where-Object { $_.PSChildName -match $phoneVid } |
                ForEach-Object {
                    Get-ChildItem -LiteralPath $_.PSPath -ErrorAction SilentlyContinue | ForEach-Object {
                        if (-not (Test-Path -LiteralPath (Join-Path $_.PSPath "Control"))) { return }
                        $props = Get-ItemProperty -LiteralPath $_.PSPath -ErrorAction SilentlyContinue
                        $name = [string]$(if ($props.FriendlyName) { $props.FriendlyName } else { $props.DeviceDesc })
                        $id = [string]$props.DeviceID
                        if (-not $id) { $id = [string]$_.PSChildName }
                        if (-not $name) { return }
                        $osHint = Resolve-MobileOsHint -FriendlyName $name -InstanceId $id
                        if ($osHint -eq "other") {
                            if ($id -match '(?i)VID_05AC' -or $name -match '(?i)iPhone|iPad|Apple') { $osHint = "ios" }
                            else { $osHint = "android" }
                        }
                        Add-MobileDevice -Id $id -Name $name -DeviceClass "USB" -Connection "usb" -OsHint $osHint -InstanceId $id
                    }
                }
        } catch {}
    }

    function Get-MobileDeviceRank {
        param($Device)
        $name = [string]$Device.name
        $cls = [string]$Device.device_class
        $score = 0
        if ($cls -eq "WPD") { $score += 100 }
        elseif ($cls -eq "portable") { $score += 80 }
        elseif ($cls -eq "USBDevice") { $score += 10 }
        if ($name -match '(?i)^(Apple )?iPhone|iPad|iPod') { $score += 50 }
        elseif ($name -match '(?i)Android|Samsung|Xiaomi|Huawei|Honor|OnePlus|Pixel|Phone|Galaxy|Redmi|Oppo|Vivo|Tecno') { $score += 40 }
        if ($name -match '(?i)^Apple Mobile Device') { $score -= 80 }
        if ($name -match '(?i)Composite Device|Camera DFU') { $score -= 100 }
        return $score
    }

    # Collapse WPD + MTP + Apple driver interfaces for the same physical phone.
    # One iPhone often appears as both "Apple iPhone" (WPD/MTP) and
    # "Apple Mobile Device USB Device" (Apple Mobile Device Support driver).
    $byKey = @{}
    foreach ($d in $devices) {
        $os = [string]$d.os_hint
        if ($os -eq "ios") {
            # One canonical iOS handset entry unless we later detect multiple UDIDs.
            $key = "ios|handset"
        }
        elseif ($os -eq "android") {
            $vidpid = ""
            foreach ($candidate in @([string]$d.instance_id, [string]$d.id)) {
                if ($candidate -match 'VID_([0-9A-Fa-f]{4}).*?PID_([0-9A-Fa-f]{4})') {
                    $vidpid = ($Matches[1] + "|" + $Matches[2]).ToUpperInvariant()
                    break
                }
            }
            $key = if ($vidpid) { "android|$vidpid" } else { ("android|{0}" -f $d.name).ToLowerInvariant() }
        }
        else {
            $key = ("{0}|{1}" -f $d.name, $os).ToLowerInvariant()
        }
        if (-not $byKey.ContainsKey($key)) {
            $byKey[$key] = $d
            continue
        }
        $existing = $byKey[$key]
        if ((Get-MobileDeviceRank $d) -gt (Get-MobileDeviceRank $existing)) {
            $byKey[$key] = $d
        }
    }

    # Prefer the Apple usbmux UDID (pymobiledevice3) over a Windows WPD instance id.
    # Skip on Android-only scans so a broken host Python cannot stall detection.
    $haveIos = @($byKey.Values | Where-Object { [string]$_.os_hint -eq "ios" }).Count -gt 0
    try {
        if (-not $haveIos) { throw "skip-usbmux-android-only" }
        $mux = @(Get-IosUsbmuxDevices)
        $udids = @($mux | ForEach-Object { [string]$_.udid } | Where-Object { $_ } | Select-Object -Unique)
        if ($udids.Count -eq 0) {
            $ideviceId = Find-IdeviceIdExe
            if ($ideviceId) {
                $listOut = & $ideviceId -l 2>&1 | Out-String
                $udids = @([regex]::Matches($listOut, "[0-9A-Fa-f]{8}-[0-9A-Fa-f]{16}|[0-9A-Fa-f]{40}") | ForEach-Object { $_.Value } | Select-Object -Unique)
            }
        }
        if ($udids.Count -ge 1) {
            $wpdIos = $null
            if ($byKey.ContainsKey("ios|handset")) {
                $wpdIos = $byKey["ios|handset"]
                $byKey.Remove("ios|handset")
            }
            foreach ($uid in $udids) {
                $muxDev = @($mux | Where-Object { $_.udid -eq $uid } | Select-Object -First 1)
                $label = if ($muxDev -and $muxDev.name) { [string]$muxDev.name } elseif ($wpdIos -and $udids.Count -eq 1) { [string]$wpdIos.name } else { "Apple iPhone" }
                if ($muxDev -and $muxDev.product) { $label = "$label ($($muxDev.product))" }
                $byKey["ios|$uid"] = [pscustomobject]@{
                    id               = $uid
                    instance_id      = $uid
                    name             = $label
                    os_hint          = "ios"
                    connection       = "usb"
                    device_class     = "usbmux"
                    has_drive_letter = $false
                    live_acquire     = $true
                    capability_label = "SUPPORTED_DIRECT_LOGICAL"
                    ios_backup_roots = $(if ($wpdIos) { $wpdIos.ios_backup_roots } else { $null })
                    guidance         = "Connected iOS device over USB (Apple usbmux). Unlock, Trust This Computer, then Start extraction."
                }
            }
        }
    }
    catch { }

    $script:DeviceCache = @($byKey.Values | Sort-Object { $_.name })
    $script:DeviceCacheAt = Get-Date
    return $script:DeviceCache
    }
    finally {
        $script:DeviceScanBusy = $false
    }
}

function Get-WorkstationDriveVolumes {
    if ($script:DriveCache -and ((Get-Date) - $script:DriveCacheAt).TotalSeconds -lt 8) {
        return $script:DriveCache
    }
    $byLetter = @{}

    function Add-DetectedVolume {
        param($Letter, $Label = '', $DriveType = 'fixed', $Size = 0, $Free = 0, $FileSystem = '')
        $L = ("$Letter").Trim().TrimEnd(':').ToUpper()
        if ($L -notmatch '^[A-Z]$') { return }
        if (-not $byLetter.ContainsKey($L)) {
            $byLetter[$L] = @{
                letter     = $L
                label      = ''
                drive_type = 'fixed'
                size_bytes = [int64]0
                free_bytes = [int64]0
                filesystem = ''
            }
        }
        $row = $byLetter[$L]
        if ($Label) { $row.label = [string]$Label }
        if ($DriveType) { $row.drive_type = [string]$DriveType }
        if ($Size) { $row.size_bytes = [int64]$Size }
        if ($Free) { $row.free_bytes = [int64]$Free }
        if ($FileSystem) { $row.filesystem = [string]$FileSystem }
    }

    # Get-Volume sees USB/JMicron external disks that Win32_LogicalDisk omits.
    try {
        Get-Volume -ErrorAction SilentlyContinue |
            Where-Object { $_.DriveLetter -and "$($_.DriveLetter)" -match '^[A-Z]$' } |
            ForEach-Object {
                $dt = ([string]$_.DriveType).ToLower()
                if ($dt -eq 'cd-rom') { $dt = 'cdrom' }
                Add-DetectedVolume -Letter $_.DriveLetter -Label $_.FileSystemLabel -DriveType $dt `
                    -Size $_.Size -Free $_.SizeRemaining -FileSystem $_.FileSystem
            }
    }
    catch { }
    try {
        Get-Partition -ErrorAction SilentlyContinue |
            Where-Object { $_.DriveLetter -and "$($_.DriveLetter)" -match '^[A-Z]$' } |
            ForEach-Object { Add-DetectedVolume -Letter $_.DriveLetter }
    }
    catch { }
    try {
        Get-CimInstance -ClassName Win32_LogicalDisk -ErrorAction SilentlyContinue |
            Where-Object { $_.DeviceID -match '^[A-Z]:$' } |
            ForEach-Object {
                $driveType = switch ([int]$_.DriveType) {
                    2 { 'removable' }
                    3 { 'fixed' }
                    4 { 'network' }
                    5 { 'cdrom' }
                    default { 'other' }
                }
                Add-DetectedVolume -Letter $_.DeviceID.TrimEnd(':') -Label $_.VolumeName `
                    -DriveType $driveType -Size $_.Size -Free $_.FreeSpace -FileSystem $_.FileSystem
            }
    }
    catch { }
    foreach ($code in 65..90) {
        $name = [string][char]$code
        if ($byLetter.ContainsKey($name)) { continue }
        if (-not (Test-Path -LiteralPath "${name}:\")) { continue }
        $info = $null
        try { $info = [System.IO.DriveInfo]::new("${name}:\") } catch { }
        Add-DetectedVolume -Letter $name `
            -Label $(if ($info -and $info.IsReady) { [string]$info.VolumeLabel } else { '' }) `
            -DriveType $(if ($info) { [string]$info.DriveType.ToString().ToLower() } else { 'other' }) `
            -Size $(if ($info -and $info.IsReady) { [int64]$info.TotalSize } else { 0 }) `
            -Free $(if ($info -and $info.IsReady) { [int64]$info.TotalFreeSpace } else { 0 })
    }

    $script:DriveCache = @($byLetter.Values | Sort-Object { $_.letter })
    $script:DriveCacheAt = Get-Date
    return $script:DriveCache
}

function Get-RefreshDriveMountsStatus {
    $state = @{
        status  = "idle"
        ok      = $null
        message = "No refresh in progress"
        drives  = @()
        error   = $null
        busy    = [bool]$script:Busy
    }
    if ($script:RefreshStatusFile -and (Test-Path -LiteralPath $script:RefreshStatusFile)) {
        try {
            $raw = Get-Content -Path $script:RefreshStatusFile -Raw -ErrorAction Stop
            $parsed = $raw | ConvertFrom-Json
            $state = @{
                status       = [string]$parsed.status
                ok           = $parsed.ok
                message      = [string]$parsed.message
                drives       = @($parsed.drives)
                required_path = $(if ($parsed.required_path) { [string]$parsed.required_path } else { $null })
                error        = $(if ($parsed.error) { [string]$parsed.error } else { $null })
                log          = $(if ($parsed.log) { [string]$parsed.log } else { "" })
                unchanged     = [bool]$parsed.unchanged
                mount_mode    = $(if ($parsed.mount_mode) { [string]$parsed.mount_mode } else { $null })
                mount_source  = $(if ($parsed.mount_source) { [string]$parsed.mount_source } else { $null })
                wsl_distro    = $(if ($parsed.wsl_distro) { [string]$parsed.wsl_distro } else { $null })
                skipped_drives = @($parsed.skipped_drives)
                compose_base  = $(if ($parsed.compose_base) { [string]$parsed.compose_base } else { $null })
                busy          = [bool]$script:Busy
                started_utc   = $(if ($parsed.started_utc) { [string]$parsed.started_utc } else { $null })
                finished_utc = $(if ($parsed.finished_utc) { [string]$parsed.finished_utc } else { $null })
                job_version   = $(if ($parsed.job_version) { [string]$parsed.job_version } else { $null })
                job_script    = $(if ($parsed.job_script) { [string]$parsed.job_script } else { $refreshJobScript })
                helper_root   = $root
            }
        }
        catch {
            $state.error = "Could not read refresh status: $($_.Exception.Message)"
        }
    }

    # Clear busy when background process finished.
    if ($script:RefreshProcess) {
        try {
            if ($script:RefreshProcess.HasExited) {
                $exitCode = $script:RefreshProcess.ExitCode
                $script:RefreshProcess = $null
                if ($state.status -in @("done", "error", "idle")) {
                    $script:Busy = $false
                }
                elseif ($state.status -eq "running") {
                    $state.status = "error"
                    $state.ok = $false
                    $state.error = "Drive mount refresh exited (code $exitCode) before reporting a result. Try again."
                    $state.message = $state.error
                    $script:Busy = $false
                    @{
                        status = "error"
                        ok = $false
                        message = $state.error
                        error = $state.error
                        drives = @($state.drives)
                    } | ConvertTo-Json -Compress | Set-Content -Path $script:RefreshStatusFile -Encoding UTF8
                }
            }
            else {
                $script:Busy = $true
                if ($state.status -eq "idle") {
                    $state.status = "running"
                    $state.message = "Refreshing drive mounts..."
                }
            }
        }
        catch {
            $script:RefreshProcess = $null
            $script:Busy = $false
        }
    }
    elseif ($state.status -in @("done", "error")) {
        $script:Busy = $false
    }
    $state.busy = [bool]$script:Busy
    return $state
}

function Format-CommandLineArgument {
    # CommandLineToArgvW: 2n backslashes before a closing quote produce n
    # backslashes and end the argument. A path such as G:\ must be emitted as
    # "G:\\" or the quote is eaten and the job sees G:" .
    param([string]$Value)
    $tail = 0
    for ($i = $Value.Length - 1; $i -ge 0; $i--) {
        if ($Value[$i] -ne '\') { break }
        $tail++
    }
    $body = if ($tail -gt 0) { $Value.Substring(0, $Value.Length - $tail) } else { $Value }
    return '"' + $body + ('\' * ($tail * 2)) + '"'
}

function Start-RefreshDriveMountsAsync {
    param([string]$RequiredPath = "")

    if (-not (Test-Path -LiteralPath $refreshJobScript)) {
        throw "Missing script: $refreshJobScript"
    }
    $required = ("$RequiredPath").Trim()
    if ($required) {
        $required = $required -replace '/', '\'
        if ($required -notmatch '^[A-Za-z]:[\\/]') {
            throw "Selected evidence path must be an absolute Windows drive path (for example G:\Evidence\Case01)."
        }
        if (-not (Test-Path -LiteralPath $required)) {
            throw "Windows cannot see the selected evidence path: $required"
        }
    }

    $current = Get-RefreshDriveMountsStatus
    if ($current.status -eq "running" -or ($script:RefreshProcess -and -not $script:RefreshProcess.HasExited)) {
        throw "Refresh already in progress"
    }

    $script:Busy = $true
    Remove-Item -LiteralPath $script:RefreshStatusFile -Force -ErrorAction SilentlyContinue
    @{
        status        = "running"
        ok            = $null
        message       = $(if ($required) { "Checking Docker access to $required..." } else { "Drive mount refresh started..." })
        drives        = @()
        required_path = $(if ($required) { $required } else { $null })
        error         = $null
        log           = ""
        started_utc   = (Get-Date).ToUniversalTime().ToString("o")
    } | ConvertTo-Json -Compress | Set-Content -Path $script:RefreshStatusFile -Encoding UTF8

    # One command-line string. Start-Process re-quotes array items that contain
    # spaces, and CommandLineToArgvW treats a backslash before the closing quote
    # as an escape: -RequiredPath "G:\" arrives as G:" and the remount aborts
    # before Docker ever sees /host/g. Doubling only the trailing slashes keeps
    # the drive root and still preserves spaces in evidence folder names.
    $cmd = @(
        "-NoProfile",
        "-ExecutionPolicy", "Bypass",
        "-File", (Format-CommandLineArgument $refreshJobScript),
        "-Root", (Format-CommandLineArgument $root),
        "-StatusFile", (Format-CommandLineArgument $script:RefreshStatusFile)
    ) -join " "
    if ($required) {
        $cmd += " -RequiredPath " + (Format-CommandLineArgument $required)
    }
    $proc = Start-Process -FilePath "powershell.exe" -ArgumentList $cmd -WindowStyle Hidden -PassThru
    $script:RefreshProcess = $proc

    return @{
        ok            = $true
        started       = $true
        status        = "running"
        required_path = $(if ($required) { $required } else { $null })
        message       = $(if ($required) {
            "Checking and mounting the selected Windows drive. API may restart briefly - keep this page open."
        } else {
            "Drive mount refresh started. API may restart briefly - keep this page open."
        })
        pid           = $proc.Id
    }
}

function Invoke-RefreshDriveMounts {
    param([string]$RequiredPath = "")
    # Back-compat sync path (unused by UI after async change).
    return Start-RefreshDriveMountsAsync -RequiredPath $RequiredPath
}

function Handle-Request {
    param([System.Net.HttpListenerContext]$Context)

    $request = $Context.Request
    $response = $Context.Response
    $path = ($request.Url.AbsolutePath.TrimEnd("/"))
    if (-not $path) { $path = "/" }

    if ($request.HttpMethod -eq "OPTIONS") {
        Write-JsonResponse -Response $response -StatusCode 204 -Body @{}
        return
    }

    if (-not (Test-Authorized -Request $request)) {
        Write-JsonResponse -Response $response -StatusCode 401 -Body @{
            ok    = $false
            error = "Unauthorized"
        }
        return
    }

    if ($request.HttpMethod -eq "GET" -and ($path -eq "/" -or $path -eq "/health")) {
        $runningJobs = @($script:AcquireJobs.Keys | Where-Object {
            $j = $script:AcquireJobs[$_]
            $j.Status -eq "running"
        })
        Write-JsonResponse -Response $response -StatusCode 200 -Body @{
            ok                 = $true
            service            = "host-drive-helper"
            port               = $Port
            bind_host          = $BindHost
            busy               = [bool]$script:Busy
            acquire_jobs       = $runningJobs.Count
            helper_version     = $script:HelperVersion
            helper_pid         = $PID
            helper_script      = $PSCommandPath
            root               = $root
            job_script         = $refreshJobScript
            job_script_version = (Get-JobScriptVersion)
            started_utc        = $script:HelperStartedUtc
        }
        return
    }

    if ($request.HttpMethod -eq "GET" -and $path -eq "/acquisition/jobs") {
        $jobs = @()
        $jobsDir = Join-Path $env:TEMP "aetheris_acq_jobs"
        if (Test-Path -LiteralPath $jobsDir) {
            foreach ($f in @(Get-ChildItem -LiteralPath $jobsDir -Filter "*.json" -ErrorAction SilentlyContinue)) {
                try {
                    $meta = Get-Content -LiteralPath $f.FullName -Raw -Encoding UTF8 | ConvertFrom-Json
                    $sid = [int]($(if ($meta.pid) { $meta.pid } else { 0 }))
                    if ($sid -le 0) { continue }
                    if (-not (Get-Process -Id $sid -ErrorAction SilentlyContinue)) { continue }
                    $detail = ""
                    $runName = ""
                    $files = 0
                    $bytes = [int64]0
                    $pf = [string]$meta.progress_file
                    if ($pf -and (Test-Path -LiteralPath $pf)) {
                        $p = Get-Content -LiteralPath $pf -Raw -ErrorAction SilentlyContinue | ConvertFrom-Json
                        $detail = [string]$p.detail
                        $runName = [string]$p.run_name
                        $files = [int]$p.files_seen
                        $bytes = [int64]$p.bytes_done
                    }
                    $caseId = [string]$meta.case_id
                    $jobs += @{
                        job_id     = $f.BaseName
                        status     = "running"
                        run_name   = $runName
                        case_id    = $caseId
                        detail     = $detail
                        files_seen = $files
                        bytes_done = $bytes
                    }
                } catch {}
            }
        }
        Write-JsonResponse -Response $response -StatusCode 200 -Body @{ ok = $true; jobs = @($jobs) }
        return
    }

    if ($request.HttpMethod -eq "GET" -and ($path -eq "/acquisition/job" -or $path.StartsWith("/acquisition/job/"))) {
        $jobId = ""
        if ($path.StartsWith("/acquisition/job/") -and $path.Length -gt "/acquisition/job/".Length) {
            $jobId = $path.Substring("/acquisition/job/".Length).Trim("/")
        }
        if (-not $jobId -and $request.Url.Query) {
            $q = [System.Web.HttpUtility]::ParseQueryString($request.Url.Query)
            $jobId = [string]$q["id"]
        }
        # Fallback without System.Web
        if (-not $jobId -and $request.Url.Query -match '[?&]id=([^&]+)') {
            $jobId = [uri]::UnescapeDataString($Matches[1])
        }
        $status = Get-AcquireJobStatus -JobId $jobId
        # Prefer a slim status for large forensic result files. Embedding a multi‑MB
        # result here blocks Docker↔host polling and leaves the UI stuck at ~70%.
        if ($status.status -in @("completed", "failed") -and $jobId -and $script:AcquireJobs.ContainsKey($jobId)) {
            $rf = $script:AcquireJobs[$jobId].ResultFile
            $pf = $script:AcquireJobs[$jobId].ProgressFile
            if ($rf -and (Test-Path -LiteralPath $rf)) {
                try {
                    $len = [int64](Get-Item -LiteralPath $rf).Length
                    $maxInline = 512KB
                    if ($len -le $maxInline) {
                        $rawResult = [System.IO.File]::ReadAllText($rf)
                        $wrapper = "{`"ok`":true,`"status`":`"$($status.status)`",`"job_id`":`"$jobId`",`"result`":$rawResult}"
                        Write-RawJsonResponse -Response $response -StatusCode 200 -Json $wrapper
                        return
                    }
                    # Peek essential fields without loading the whole document into ConvertTo-Json.
                    $head = ""
                    $fs = [System.IO.File]::OpenRead($rf)
                    try {
                        $buf = New-Object byte[] ([Math]::Min(65536, $len))
                        $n = $fs.Read($buf, 0, $buf.Length)
                        $head = [System.Text.Encoding]::UTF8.GetString($buf, 0, $n)
                    } finally { $fs.Close() }
                    $runName = ""
                    if ($head -match '"run_name"\s*:\s*"([^"]+)"') { $runName = $Matches[1] }
                    $stage = $status.status
                    if ($head -match '"stage_reached"\s*:\s*"([^"]+)"') { $stage = $Matches[1] }
                    $okVal = ($status.status -eq "completed")
                    if ($head -match '"ok"\s*:\s*false') { $okVal = $false }
                    Write-JsonResponse -Response $response -StatusCode 200 -Body @{
                        ok           = $true
                        status       = $status.status
                        job_id       = $jobId
                        result_file  = $rf
                        result_bytes = $len
                        progress     = $pf
                        result       = @{
                            ok            = $okVal
                            run_name      = $runName
                            stage_reached = $(if ($stage) { $stage } else { "complete" })
                            paths         = @{}
                            errors        = @()
                            warnings      = @("Full host result is large ($([math]::Round($len/1MB,1)) MB); API will recover sealed paths from disk.")
                            acquisition_record = @{}
                            evidence_package = @{ run_name = $runName; complete = $okVal; extraction_data = @() }
                        }
                    }
                    return
                } catch {}
            }
        }
        Write-JsonResponse -Response $response -StatusCode 200 -Body $status
        return
    }

    if ($request.HttpMethod -eq "GET" -and $path -eq "/drives") {
        try {
            $volumes = Get-WorkstationDriveVolumes
            $letters = @($volumes | ForEach-Object { $_.letter })
            $mobileDevices = @(Get-ConnectedMobileDevices)
            Write-JsonResponse -Response $response -StatusCode 200 -Body @{
                ok             = $true
                drives         = $letters
                volumes        = $volumes
                count          = $letters.Count
                mobile_devices = $mobileDevices
                mobile_count   = $mobileDevices.Count
            }
        }
        catch {
            Write-JsonResponse -Response $response -StatusCode 500 -Body @{
                ok    = $false
                error = $_.Exception.Message
            }
        }
        return
    }

    if ($request.HttpMethod -eq "GET" -and ($path -eq "/mobile-devices" -or $path -eq "/mobile_devices")) {
        try {
            $mobileDevices = @(Get-ConnectedMobileDevices)
            Write-JsonResponse -Response $response -StatusCode 200 -Body @{
                ok             = $true
                mobile_devices = $mobileDevices
                count          = $mobileDevices.Count
                ios_backup_roots = @()
            }
        }
        catch {
            Write-JsonResponse -Response $response -StatusCode 500 -Body @{
                ok    = $false
                error = $_.Exception.Message
            }
        }
        return
    }

    if ($request.HttpMethod -eq "GET" -and $path -eq "/acquisition/adapters") {
        try {
            if (-not (Test-Path -LiteralPath $script:AdaptersCacheFile)) { Write-HostAdapterCache }
            $raw = Get-Content -LiteralPath $script:AdaptersCacheFile -Raw
            Write-RawJsonResponse -Response $response -StatusCode 200 -Json $raw
        } catch {
            Write-JsonResponse -Response $response -StatusCode 200 -Body @{
                ok = $true
                adapters = @(
                    @{ name = "android_mtp"; os_family = "android"; available = $true; reason = "Windows MTP/WPD ready"; via = "host" }
                    @{ name = "android_adb"; os_family = "android"; available = $true; reason = "Host USB helper"; via = "host" }
                    @{ name = "ios_lockdown"; os_family = "ios"; available = $true; reason = "Host USB helper"; via = "host" }
                )
            }
        }
        return
    }

    if ($request.HttpMethod -eq "GET" -and $path -eq "/acquisition/devices") {
        try {
            $devices = @(); $warnings = @()
            $iosSeen = @{}
            $sim = @{ available = $false; readers = @(); reason = "" }
            try { $sim = Get-PcscSimStatus } catch {}
            foreach ($reader in @($sim.readers)) {
                if ($reader) {
                    $devices += @{ adapter = "sim_reader"; device_id = [string]$reader; label = ("SIM reader (" + $reader + ")"); status = "reader"; os_family = "sim" }
                }
            }
            # WPD/MTP phones (old Android without USB debugging, file-transfer mode).
            $adbIds = @($devices | Where-Object { $_.adapter -eq "android_adb" } | ForEach-Object { [string]$_.device_id })
            foreach ($wpd in @(Get-ConnectedMobileDevices)) {
                $os = [string]$wpd.os_hint
                $wid = [string]$wpd.id
                $winst = [string]$wpd.instance_id
                if ($os -eq "ios") {
                    if ($iosSeen.ContainsKey($wid)) { continue }
                    if ($iosSeen.Count -gt 0) { continue }
                    $devices += @{
                        adapter     = "ios_lockdown"
                        device_id   = $wid
                        label       = [string]$wpd.name
                        status      = "wpd"
                        os_family   = "ios"
                        instance_id = $winst
                        connection  = [string]$wpd.connection
                    }
                    continue
                }
                $dupAdb = $false
                foreach ($sid in $adbIds) {
                    if (-not $sid) { continue }
                    if ($wid -match [regex]::Escape($sid) -or $winst -match [regex]::Escape($sid)) {
                        $dupAdb = $true
                        break
                    }
                }
                if ($dupAdb) { continue }
                $already = $false
                foreach ($ex in $devices) {
                    if ([string]$ex.device_id -eq $wid) { $already = $true; break }
                }
                if ($already) { continue }
                $devices += @{
                    adapter     = "android_mtp"
                    device_id   = $wid
                    label       = $(if ($wpd.name) { [string]$wpd.name } else { "Android (MTP)" })
                    status      = $(if ([string]$wpd.connection -eq "mtp") { "mtp" } else { "wpd" })
                    os_family   = "android"
                    instance_id = $winst
                    connection  = [string]$wpd.connection
                }
            }
            Write-JsonResponse -Response $response -StatusCode 200 -Body @{ ok = $true; devices = @($devices); warnings = @($warnings); count = @($devices).Count }
        } catch {
            # Still return WPD/MTP phones so the UI can detect without ADB/usbmux.
            $fallback = @()
            try {
                foreach ($wpd in @(Get-ConnectedMobileDevices)) {
                    $os = [string]$wpd.os_hint
                    $fallback += @{
                        adapter     = $(if ($os -eq "ios") { "ios_lockdown" } else { "android_mtp" })
                        device_id   = [string]$wpd.id
                        label       = [string]$wpd.name
                        status      = "wpd"
                        os_family   = $(if ($os) { $os } else { "android" })
                        instance_id = [string]$wpd.instance_id
                        connection  = [string]$wpd.connection
                    }
                }
            } catch {}
            Write-JsonResponse -Response $response -StatusCode 200 -Body @{
                ok = $true
                devices = $fallback
                warnings = @($_.Exception.Message)
                count = $fallback.Count
            }
        }
        return
    }
    if ($request.HttpMethod -eq "POST" -and $path -eq "/acquisition/cancel") {
        try {
            $payload = Read-RequestJson -Request $request
            $jobId = ""
            $progressFile = ""
            if ($payload.job_id) { $jobId = [string]$payload.job_id }
            if ($payload.progress_file) { $progressFile = [string]$payload.progress_file }
            $result = Stop-AcquireJob -JobId $jobId -ProgressFile $progressFile
            Write-JsonResponse -Response $response -StatusCode 200 -Body $result
        }
        catch {
            Write-JsonResponse -Response $response -StatusCode 500 -Body @{
                ok    = $false
                error = $_.Exception.Message
            }
        }
        return
    }
    if ($request.HttpMethod -eq "POST" -and $path -eq "/acquisition/remove") {
        try {
            $payload = Read-RequestJson -Request $request
            $extra = @{}
            if ($payload.paths) {
                foreach ($k in @("original", "working", "logs", "hashes", "exports", "case_root", "output_path")) {
                    $v = [string]$payload.paths.$k
                    if ($v) { $extra[$k] = $v }
                }
            }
            $jobId = ""
            $runName = ""
            $caseId = ""
            $progressFile = ""
            if ($payload.job_id) { $jobId = [string]$payload.job_id }
            if ($payload.run_name) { $runName = [string]$payload.run_name }
            if ($payload.case_id) { $caseId = [string]$payload.case_id }
            if ($payload.progress_file) { $progressFile = [string]$payload.progress_file }
            $result = Remove-AcquireRunData -JobId $jobId -RunName $runName -CaseId $caseId -ProgressFile $progressFile -ExtraPaths $extra
            Write-JsonResponse -Response $response -StatusCode 200 -Body $result
        }
        catch {
            Write-JsonResponse -Response $response -StatusCode 500 -Body @{
                ok    = $false
                error = $_.Exception.Message
            }
        }
        return
    }
    if ($request.HttpMethod -eq "POST" -and $path -eq "/acquisition/preview") {
        try {
            $payload = Read-RequestJson -Request $request
            $adapterName = [string]$payload.adapter
            $deviceId = [string]$payload.device_id
            $nameHint = [string]($(if ($payload.label) { $payload.label } elseif ($payload.device_name) { $payload.device_name } else { "" }))
            if (-not $adapterName -or -not $deviceId) { throw "adapter and device_id are required" }
            # MTP/WPD identify must not depend on a working host Python (broken venvs
            # previously returned 500 and the UI showed a Docker USB error).
            if ($adapterName -in @("android_mtp", "android_adb", "ios_lockdown")) {
                $native = New-HostDevicePreview -Adapter $adapterName -DeviceId $deviceId -NameHint $nameHint
                Write-JsonResponse -Response $response -StatusCode 200 -Body $native
                return
            }
            $backend = Join-Path $root "backend"
            $py = Get-HostPython
            if (-not $py) {
                Write-JsonResponse -Response $response -StatusCode 200 -Body (New-HostDevicePreview -Adapter $adapterName -DeviceId $deviceId)
                return
            }
            $pt = Join-Path $root "tools\platform-tools"
            $lid = Join-Path $root "tools\libimobiledevice"
            $extraPath = Join-Path $env:LOCALAPPDATA "Android\Sdk\platform-tools"
            $env:PATH = ($pt + ";" + $lid + ";" + $extraPath + ";" + $env:PATH)
            $env:PYTHONPATH = $backend
            $stamp = [guid]::NewGuid().ToString("N")
            $tmpPy = Join-Path $env:TEMP ("acq_preview_" + $stamp + ".py")
            $tmpJson = Join-Path $env:TEMP ("acq_preview_" + $stamp + ".json")
            $tmpOut = Join-Path $env:TEMP ("acq_preview_" + $stamp + ".out")
            $tmpErr = Join-Path $env:TEMP ("acq_preview_" + $stamp + ".err")
            $previewPayload = @{ adapter = [string]$payload.adapter; device_id = [string]$payload.device_id }
            [System.IO.File]::WriteAllText($tmpJson, ($previewPayload | ConvertTo-Json -Depth 6), [System.Text.UTF8Encoding]::new($false))
            $pySource = "import json,sys`nfrom pathlib import Path`nfrom app.services.mobile_acquire import CollectionOrchestrator, DeviceDetector`npayload=json.loads(Path(sys.argv[1]).read_text(encoding='utf-8-sig'))`nprint(json.dumps(CollectionOrchestrator(DeviceDetector()).preview(payload['adapter'], payload['device_id']), default=str))`n"
            [System.IO.File]::WriteAllText($tmpPy, $pySource, [System.Text.UTF8Encoding]::new($false))
            $proc = Start-Process -FilePath $py -ArgumentList @($tmpPy, $tmpJson) -WorkingDirectory $backend -RedirectStandardOutput $tmpOut -RedirectStandardError $tmpErr -NoNewWindow -Wait -PassThru
            $stdout = if (Test-Path -LiteralPath $tmpOut) { Get-Content -LiteralPath $tmpOut -Raw -EA SilentlyContinue } else { "" }
            $stderr = if (Test-Path -LiteralPath $tmpErr) { Get-Content -LiteralPath $tmpErr -Raw -EA SilentlyContinue } else { "" }
            foreach ($f in @($tmpPy, $tmpJson, $tmpOut, $tmpErr)) { Remove-Item -LiteralPath $f -Force -EA SilentlyContinue }
            $jsonLine = $null
            if ($stdout) { $jsonLine = ($stdout -split "`r?`n" | Where-Object { $_.Trim().StartsWith("{") } | Select-Object -Last 1) }
            if (-not $jsonLine) { throw ("Preview produced no JSON: " + $stdout + " " + $stderr) }
            Write-JsonResponse -Response $response -StatusCode 200 -Body ($jsonLine | ConvertFrom-Json)
        } catch {
            try {
                Write-JsonResponse -Response $response -StatusCode 200 -Body (New-HostDevicePreview -Adapter ([string]$payload.adapter) -DeviceId ([string]$payload.device_id))
            } catch {
                Write-JsonResponse -Response $response -StatusCode 500 -Body @{ ok = $false; error = $_.Exception.Message }
            }
        }
        return
    }

    if ($request.HttpMethod -eq "POST" -and $path -eq "/acquisition/run") {
        # Async: start Python and return immediately so /health and adapters stay up.
        # Browse / register stay available. Only a live USB acquire blocks another USB acquire.
        if (Test-UsbAcquireInProgress) {
            Write-UsbBusyResponse -Response $response
            return
        }
        try {
            $payload = Read-RequestJson -Request $request
            $caseRoot = [string]$payload.case_root
            if ($caseRoot -match '^[\\/]evidence([\\/]|$)') {
                $rel = ($caseRoot -replace '^[\\/]evidence[\\/]?', '' -replace '/', '\')
                $caseRoot = if ($rel) { Join-Path (Join-Path $root "evidence") $rel } else { Join-Path $root "evidence\cases" }
            } elseif (-not $caseRoot -or $caseRoot -eq "/evidence/cases" -or $caseRoot -eq "\evidence\cases") {
                $caseRoot = Join-Path $root "evidence\cases"
            }
            New-Item -ItemType Directory -Force -Path $caseRoot | Out-Null
            $stamp = [guid]::NewGuid().ToString("N")
            $tmpResult = Join-Path $env:TEMP ("acq_result_" + $stamp + ".json")
            $cloudBoxes = @()
            if ($payload.cloud_mailboxes) { $cloudBoxes = @($payload.cloud_mailboxes) }
            $runPayload = @{
                case_id = [string]$payload.case_id
                evidence_id = [string]$payload.evidence_id
                examiner = [string]($(if ($payload.examiner) { $payload.examiner } else { "host-acquire" }))
                legal_authority = [string]$payload.legal_authority
                case_root = $caseRoot
                adapter = [string]$payload.adapter
                device_id = [string]$payload.device_id
                objective_methods = @($payload.objective_methods)
                authorized_methods = @($payload.authorized_methods)
                method_override = $(if ($payload.method_override) { [string]$payload.method_override } else { $null })
                cable_adapter_asset_id = [string]($(if ($payload.cable_adapter_asset_id) { $payload.cable_adapter_asset_id } else { "" }))
                license_endpoint_id = [string]($(if ($payload.license_endpoint_id) { $payload.license_endpoint_id } else { "" }))
                backup_password = $(if ($null -ne $payload.backup_password -and [string]$payload.backup_password) { [string]$payload.backup_password } else { $null })
                examiner_notes = [string]($(if ($payload.examiner_notes) { $payload.examiner_notes } else { "" }))
                device_label = [string]($(if ($payload.device_label) { $payload.device_label } elseif ($payload.label) { $payload.label } else { "" }))
                device_condition = [string]($(if ($payload.device_condition) { $payload.device_condition } else { "" }))
                network_isolated = $payload.network_isolated
                create_working_copy = [bool]($(if ($null -ne $payload.create_working_copy) { $payload.create_working_copy } else { $true }))
                cloud_mailboxes = $cloudBoxes
                progress_file = [string]($(if ($payload.progress_file) { $payload.progress_file } else { "" }))
                result_file = $tmpResult
            }
            if (-not $runPayload.progress_file) {
                $runPayload.progress_file = Join-Path $caseRoot (".acq_progress_" + [guid]::NewGuid().ToString("N") + ".json")
            }
            $backend = Join-Path $root "backend"
            $adapterName = [string]$runPayload.adapter
            if ($adapterName -eq "android_mtp" -or $adapterName -match 'mtp') {
                Start-NativeMtpAcquireJob -RunPayload $runPayload -Stamp $stamp -TmpResult $tmpResult
                Write-JsonResponse -Response $response -StatusCode 202 -Body @{
                    ok                 = $true
                    async              = $true
                    job_id             = $stamp
                    status             = "running"
                    busy               = $true
                    progress           = [string]$runPayload.progress_file
                    via                = "native_mtp"
                    owner_agent        = "androidagent"
                    owner_agent_label  = "Android Agent"
                    os_family          = "android"
                }
                return
            }
            if ($adapterName -eq "ios_lockdown" -or $adapterName -match 'ios') {
                $iosJob = Join-Path $root "scripts\native_ios_job.ps1"
                $payloadFile = Join-Path $env:TEMP ("acq_ios_" + $stamp + ".json")
                $tmpOut = Join-Path $env:TEMP ("acq_ios_" + $stamp + ".out")
                $tmpErr = Join-Path $env:TEMP ("acq_ios_" + $stamp + ".err")
                [System.IO.File]::WriteAllText($payloadFile, ($runPayload | ConvertTo-Json -Depth 20), [System.Text.UTF8Encoding]::new($false))
                $script:Busy = $true
                $script:AcquireBusy = $true
                $proc = Start-Process -FilePath "powershell.exe" -ArgumentList @(
                    "-STA", "-NoProfile", "-ExecutionPolicy", "Bypass", "-File", $iosJob,
                    "-PayloadFile", $payloadFile, "-ResultFile", $tmpResult
                ) -WorkingDirectory $root -WindowStyle Minimized -PassThru -RedirectStandardOutput $tmpOut -RedirectStandardError $tmpErr
                Write-AcquireJobSidecar -JobId $stamp -ProcessId $proc.Id -ResultFile $tmpResult -ProgressFile ([string]$runPayload.progress_file) -CaseId ([string]$runPayload.case_id)
                $script:AcquireJobs[$stamp] = @{
                    Pid = $proc.Id; ResultFile = $tmpResult; ProgressFile = [string]$runPayload.progress_file
                    ErrFile = $tmpErr; OutFile = $tmpOut; Status = "running"; Error = ""; StartedUtc = (Get-Date).ToUniversalTime().ToString("o")
                }
                Write-JsonResponse -Response $response -StatusCode 202 -Body @{
                    ok = $true; async = $true; job_id = $stamp; status = "running"; busy = $true
                    progress = [string]$runPayload.progress_file; via = "native_ios"
                    owner_agent = "iosagent"; owner_agent_label = "iOS Agent"; os_family = "ios"
                }
                return
            }
            $py = Get-HostPython
            if (-not $py) {
                throw "Examiner kit Python is not available. Restart scripts\ensure-host-drive-helper.ps1 -ForceRestart and retry."
            }
            $pt = Join-Path $root "tools\platform-tools"
            $lid = Join-Path $root "tools\libimobiledevice"
            $extraPath = Join-Path $env:LOCALAPPDATA "Android\Sdk\platform-tools"
            $env:PATH = ($pt + ";" + $lid + ";" + $extraPath + ";" + $env:PATH)
            $env:PYTHONPATH = $backend
            $tmpPy = Join-Path $env:TEMP ("acq_run_" + $stamp + ".py")
            $tmpJson = Join-Path $env:TEMP ("acq_run_" + $stamp + ".json")
            $tmpOut = Join-Path $env:TEMP ("acq_run_" + $stamp + ".out")
            $tmpErr = Join-Path $env:TEMP ("acq_run_" + $stamp + ".err")
            [System.IO.File]::WriteAllText($tmpJson, ($runPayload | ConvertTo-Json -Depth 20), [System.Text.UTF8Encoding]::new($false))
            $pyLines = @(
                'import json, sys, traceback'
                'from pathlib import Path'
                'from app.services.mobile_acquire import AcquisitionRequest, CollectionMethod, CollectionOrchestrator, DeviceDetector'
                'payload = json.loads(Path(sys.argv[1]).read_text(encoding="utf-8-sig"))'
                'override = payload.get("method_override") or None'
                'progress_file = payload.get("progress_file") or ""'
                'result_file = payload.get("result_file") or ""'
                'def _write_progress(event):'
                '    if not progress_file: return'
                '    try: Path(progress_file).write_text(json.dumps(event, default=str), encoding="utf-8")'
                '    except Exception: pass'
                'def _write_result(obj):'
                '    text = json.dumps(obj, default=str)'
                '    if result_file:'
                '        try: Path(result_file).write_text(text, encoding="utf-8")'
                '        except Exception: pass'
                '    print(text, flush=True)'
                'def _on_progress(event):'
                '    if isinstance(event, dict): _write_progress(event)'
                'cancel_file = (progress_file or "") + ".cancel"'
                'def _cancelled():'
                '    try: return bool(cancel_file and Path(cancel_file).exists())'
                '    except Exception: return False'
                'req = AcquisitionRequest('
                '    case_id=payload["case_id"], evidence_id=payload["evidence_id"],'
                '    examiner=payload.get("examiner") or "host-acquire", legal_authority=payload["legal_authority"],'
                '    case_root=payload["case_root"], adapter_name=payload["adapter"], device_id=payload["device_id"],'
                '    objective_methods=[CollectionMethod(m) for m in (payload.get("objective_methods") or []) if m],'
                '    authorized_methods=[CollectionMethod(m) for m in (payload.get("authorized_methods") or []) if m],'
                '    examiner_method_override=CollectionMethod(override) if override else None,'
                '    cable_adapter_asset_id=payload.get("cable_adapter_asset_id") or "",'
                '    license_endpoint_id=payload.get("license_endpoint_id") or "",'
                '    backup_password=payload.get("backup_password"),'
                '    examiner_notes=payload.get("examiner_notes") or "",'
                '    device_condition=payload.get("device_condition") or "",'
                '    network_isolated=payload.get("network_isolated"),'
                '    create_working_copy=bool(payload.get("create_working_copy", True)),'
                '    cloud_mailboxes=list(payload.get("cloud_mailboxes") or []),'
                ')'
                '_write_progress({"stage":"acquire","item":"host_usb_bridge","bytes_done":0,"detail":"Host USB bridge connected","category":"Preparing"})'
                'try:'
                '    result = CollectionOrchestrator(DeviceDetector(), progress=_on_progress, cancel=_cancelled).run(req)'
                '    try: _final_bytes = int((result.acquisition_record or {}).get("output_size") or 0)'
                '    except Exception: _final_bytes = 0'
                '    _write_progress({"stage": result.stage_reached or "complete", "item":"complete", "bytes_done": _final_bytes, "run_name": result.run_name, "detail":"Collection finished", "category":"Complete"})'
                '    _write_result({"ok": result.ok, **result.as_dict()})'
                'except Exception as exc:'
                '    traceback.print_exc()'
                '    _write_result({"ok": False, "error": str(exc), "errors": [str(exc)], "stage_reached": "failed", "method_decision": {"selected": None, "considered": [], "rejected": {}, "rationale": "Host acquisition failed before method selection completed.", "deeper_available": []}, "limitations": ["Host USB acquisition failed."], "evidence_package": {"run_name": "", "extraction_data": [], "complete": False}, "acquisition_record": {"output_size": 0, "missing_fields": []}, "paths": {}, "chain_of_custody": []})'
                '    sys.exit(1)'
            )
            [System.IO.File]::WriteAllText($tmpPy, ($pyLines -join "`n"), [System.Text.UTF8Encoding]::new($false))
            $script:Busy = $true
            $script:AcquireBusy = $true
            $proc = Start-Process -FilePath $py -ArgumentList @($tmpPy, $tmpJson) -WorkingDirectory $backend -RedirectStandardOutput $tmpOut -RedirectStandardError $tmpErr -NoNewWindow -PassThru
            $script:AcquireJobs[$stamp] = @{
                Pid          = $proc.Id
                ResultFile   = $tmpResult
                ProgressFile = [string]$runPayload.progress_file
                ErrFile      = $tmpErr
                OutFile      = $tmpOut
                Status       = "running"
                Error        = ""
                StartedUtc   = (Get-Date).ToUniversalTime().ToString("o")
            }
            Write-JsonResponse -Response $response -StatusCode 202 -Body @{
                ok       = $true
                async    = $true
                job_id   = $stamp
                status   = "running"
                busy     = $true
                progress = [string]$runPayload.progress_file
            }
        } catch {
            $script:Busy = $false
            $script:AcquireBusy = $false
            $msg = [string]$_.Exception.Message
            Write-JsonResponse -Response $response -StatusCode 500 -Body @{
                ok = $false; error = $msg; errors = @($msg); stage_reached = "failed"
                method_decision = @{ selected = $null; considered = @(); rejected = @{}; rationale = "Host acquisition failed before method selection completed."; deeper_available = @() }
                limitations = @("Host USB acquisition failed.")
                evidence_package = @{ run_name = ""; extraction_data = @(); complete = $false }
                acquisition_record = @{ output_size = 0; missing_fields = @() }
                paths = @{}; chain_of_custody = @()
            }
        }
        return
    }
    if ($request.HttpMethod -eq "POST" -and ($path -eq "/resolve-folder" -or $path -eq "/resolve_folder")) {
        try {
            $payload = Read-RequestJson -Request $request
            $filenames = @()
            if ($payload.filenames) { $filenames = @($payload.filenames) }
            elseif ($payload.files) { $filenames = @($payload.files) }
            $relativePaths = @()
            if ($payload.relative_paths) { $relativePaths = @($payload.relative_paths) }
            elseif ($payload.paths) { $relativePaths = @($payload.paths) }
            $folderHint = ""
            if ($payload.folder_hint) { $folderHint = [string]$payload.folder_hint }
            elseif ($payload.folder) { $folderHint = [string]$payload.folder }
            elseif ($payload.relative_path) { $folderHint = [string]$payload.relative_path }
            $result = Invoke-ResolveFolder -Filenames $filenames -FolderHint $folderHint -RelativePaths $relativePaths
            Write-JsonResponse -Response $response -StatusCode 200 -Body $result
        }
        catch {
            Write-JsonResponse -Response $response -StatusCode 500 -Body @{
                ok    = $false
                path  = $null
                error = $_.Exception.Message
            }
        }
        return
    }

    if ($request.HttpMethod -eq "POST" -and ($path -eq "/list-dir" -or $path -eq "/list_dir")) {
        try {
            $payload = Read-RequestJson -Request $request
            $listPath = ""
            if ($payload.path) { $listPath = [string]$payload.path }
            elseif ($payload.folder) { $listPath = [string]$payload.folder }
            $result = Invoke-ListDir -Path $listPath
            Write-JsonResponse -Response $response -StatusCode 200 -Body $result
        }
        catch {
            Write-JsonResponse -Response $response -StatusCode 400 -Body @{
                ok      = $false
                path    = $null
                count   = 0
                entries = @()
                error   = $_.Exception.Message
            }
        }
        return
    }

    if ($request.HttpMethod -eq "POST" -and ($path -eq "/stage-folder" -or $path -eq "/stage_folder")) {
        try {
            $payload = Read-RequestJson -Request $request
            $srcPath = ""
            if ($payload.path) { $srcPath = [string]$payload.path }
            elseif ($payload.folder) { $srcPath = [string]$payload.folder }
            $jobId = ""
            if ($payload.job_id) { $jobId = [string]$payload.job_id }
            elseif ($payload.jobId) { $jobId = [string]$payload.jobId }
            $result = Invoke-StageFolder -Path $srcPath -JobId $jobId
            Write-JsonResponse -Response $response -StatusCode 200 -Body $result
        }
        catch {
            Write-JsonResponse -Response $response -StatusCode 400 -Body @{
                ok     = $false
                path   = $null
                dest   = $null
                error  = $_.Exception.Message
            }
        }
        return
    }

    if ($request.HttpMethod -eq "GET" -and ($path -eq "/refresh-drive-mounts" -or $path -eq "/refresh-drive-mounts/status")) {
        $state = Get-RefreshDriveMountsStatus
        Write-JsonResponse -Response $response -StatusCode 200 -Body $state
        return
    }

    if ($request.HttpMethod -eq "POST" -and $path -eq "/refresh-drive-mounts") {
        try {
            $payload = Read-RequestJson -Request $request
            $requiredPath = ""
            if ($payload.required_path) { $requiredPath = [string]$payload.required_path }
            elseif ($payload.path) { $requiredPath = [string]$payload.path }
            $result = Start-RefreshDriveMountsAsync -RequiredPath $requiredPath
            Write-JsonResponse -Response $response -StatusCode 202 -Body $result
        }
        catch {
            $statusCode = 500
            if ($_.Exception.Message -match 'already in progress') {
                $statusCode = 409
            }
            elseif ($_.Exception.Message -match 'absolute Windows drive path|Windows cannot see') {
                $statusCode = 400
            }
            Write-JsonResponse -Response $response -StatusCode $statusCode -Body @{
                ok    = $false
                error = $_.Exception.Message
            }
        }
        return
    }

    if ($request.HttpMethod -eq "POST" -and ($path -eq "/acquire" -or $path -eq "/mobile-acquire")) {
        if (-not (Get-Command Invoke-MobileAcquire -ErrorAction SilentlyContinue)) {
            Write-JsonResponse -Response $response -StatusCode 500 -Body @{
                ok    = $false
                error = "Mobile acquire script not loaded (scripts/host-mobile-acquire.ps1)"
            }
            return
        }
        if (Test-UsbAcquireInProgress) {
            Write-UsbBusyResponse -Response $response
            return
        }
        $script:Busy = $true
        $script:AcquireBusy = $true
        try {
            $payload = Read-RequestJson -Request $request
            $jobId = ""
            if ($payload.job_id) { $jobId = [string]$payload.job_id }
            elseif ($payload.mobile_job_id) { $jobId = [string]$payload.mobile_job_id }
            if (-not $jobId) { throw "job_id is required" }

            $deviceId = ""
            if ($payload.device_id) { $deviceId = [string]$payload.device_id }
            elseif ($payload.id) { $deviceId = [string]$payload.id }

            $deviceName = ""
            if ($payload.device_name) { $deviceName = [string]$payload.device_name }
            elseif ($payload.name) { $deviceName = [string]$payload.name }

            $osHint = "other"
            if ($payload.os_hint) { $osHint = [string]$payload.os_hint }
            elseif ($payload.mobile_os) { $osHint = [string]$payload.mobile_os }

            $instanceId = ""
            if ($payload.instance_id) { $instanceId = [string]$payload.instance_id }

            $outputRoot = ""
            if ($payload.output_root) { $outputRoot = [string]$payload.output_root }

            if (-not $deviceName) {
                $detected = @(Get-ConnectedMobileDevices)
                if ($detected.Count -gt 0) {
                    $match = $detected | Where-Object { $_.id -eq $deviceId } | Select-Object -First 1
                    if (-not $match) { $match = $detected[0] }
                    $deviceName = [string]$match.name
                    if (-not $deviceId) { $deviceId = [string]$match.id }
                    if (-not $osHint -or $osHint -eq "other") { $osHint = [string]$match.os_hint }
                    if (-not $instanceId) { $instanceId = [string]$match.instance_id }
                }
            }

            $result = Invoke-MobileAcquire `
                -JobId $jobId `
                -DeviceId $deviceId `
                -DeviceName $deviceName `
                -OsHint $osHint `
                -InstanceId $instanceId `
                -OutputRoot $outputRoot
            Write-JsonResponse -Response $response -StatusCode 200 -Body $result
        }
        catch {
            Write-JsonResponse -Response $response -StatusCode 500 -Body @{
                ok    = $false
                error = $_.Exception.Message
            }
        }
        finally {
            $script:Busy = $false
            $script:AcquireBusy = $false
        }
        return
    }

    Write-JsonResponse -Response $response -StatusCode 404 -Body @{
        ok    = $false
        error = "Not found"
    }
}

if ($PSVersionTable.PSVersion.Major -lt 5) {
    Write-Error "PowerShell 5.1 or later is required."
}

$listener = New-Object System.Net.HttpListener
$listenPrefix = "http://$BindHost`:$Port/"
$listener.Prefixes.Add($listenPrefix)
try {
    $listener.Start()
}
catch {
    if ($BindHost -eq "+") {
        throw "Could not bind $listenPrefix. Run scripts\configure-host-drive-helper-network.ps1 as Administrator once, then restart the helper. $($_.Exception.Message)"
    }
    throw
}
Start-DrivePresenceWatcher
Write-HostAdapterCache
Write-MobileDeviceCaches
Start-MobileDeviceRefresh

Add-Type -TypeDefinition @"
using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Net;
using System.Text;
using System.Text.RegularExpressions;
using System.Threading;
public class AetherisHelperDispatcher {
  public readonly BlockingCollection<HttpListenerContext> Queue = new BlockingCollection<HttpListenerContext>();
  HttpListener _listener;
  Thread _thread;
  volatile bool _stop;
  public string HealthJson = "{\"ok\":true,\"service\":\"host-drive-helper\"}";
  public string AdaptersJsonPath = "";
  public string DevicesJsonPath = "";
  public string MobileJsonPath = "";
  public string RootPath = "";
  public string NativeMtpJobScript = "";
  public string NativeIosJobScript = "";
  public string JobsDir = "";
  int _liveBusy;
  int _liveFiles;
  long _liveBytes;
  string _liveNewest = "";
  string _livePath = "";
  public string DefaultAdaptersJson = "{\"ok\":true,\"adapters\":[{\"name\":\"android_mtp\",\"os_family\":\"android\",\"available\":true,\"reason\":\"Windows MTP/WPD ready\",\"via\":\"host\"},{\"name\":\"android_adb\",\"os_family\":\"android\",\"available\":true,\"reason\":\"Host USB helper\",\"via\":\"host\"},{\"name\":\"ios_lockdown\",\"os_family\":\"ios\",\"available\":true,\"reason\":\"Host USB helper\",\"via\":\"host\"}]}";
  public string DefaultDevicesJson = "{\"ok\":true,\"devices\":[],\"warnings\":[],\"count\":0}";
  public void Start(HttpListener listener) {
    _listener = listener;
    _thread = new Thread(AcceptLoop);
    _thread.IsBackground = true;
    _thread.Name = "aetheris-helper-accept";
    _thread.Start();
  }
  void AcceptLoop() {
    while (!_stop && _listener != null && _listener.IsListening) {
      try {
        HttpListenerContext ctx = _listener.GetContext();
        string path = "";
        string query = "";
        if (ctx.Request.Url != null) {
          path = ctx.Request.Url.AbsolutePath.TrimEnd('/');
          query = ctx.Request.Url.Query ?? "";
        }
        string method = ctx.Request.HttpMethod ?? "";
        if (method == "OPTIONS") WriteCors(ctx);
        else if (path == "" || path == "/" || path == "/health") WriteHealth(ctx);
        else if (method == "POST" && path == "/acquisition/preview") WriteNativePreview(ctx);
        else if (method == "POST" && path == "/acquisition/run" &&
                 query.IndexOf("native=", StringComparison.OrdinalIgnoreCase) >= 0) WriteNativeUsbRun(ctx, query);
        else if (method == "POST" && path == "/acquisition/cancel") WriteCancelUsb(ctx);
        else if (method == "GET" && path == "/acquisition/jobs") WriteJobList(ctx);
        else if (method == "GET" && (path == "/acquisition/job" || path.StartsWith("/acquisition/job/"))) {
          if (!WriteJobStatus(ctx, path, query)) Queue.Add(ctx);
        }
        else if (method == "GET" && path == "/acquisition/adapters") WriteCached(ctx, AdaptersJsonPath, DefaultAdaptersJson);
        else if (method == "GET" && path == "/acquisition/devices") WriteCached(ctx, DevicesJsonPath, DefaultDevicesJson);
        else if (method == "GET" && (path == "/mobile-devices" || path == "/mobile_devices")) WriteMobileDevices(ctx);
        else Queue.Add(ctx);
      } catch (HttpListenerException) { break; }
      catch (ObjectDisposedException) { break; }
      catch { }
    }
  }
  static string JsonStr(string json, string key) {
    if (string.IsNullOrEmpty(json) || string.IsNullOrEmpty(key)) return "";
    string needle = "\"" + key + "\"";
    int i = json.IndexOf(needle, StringComparison.OrdinalIgnoreCase);
    if (i < 0) return "";
    i = json.IndexOf(':', i + needle.Length);
    if (i < 0) return "";
    i++;
    while (i < json.Length && char.IsWhiteSpace(json[i])) i++;
    if (i >= json.Length) return "";
    if (json[i] == 'n' && json.IndexOf("null", i, StringComparison.OrdinalIgnoreCase) == i) return "";
    if (json[i] == 't' || json[i] == 'f' || json[i] == '{' || json[i] == '[') return "";
    if (json[i] != '"') return "";
    StringBuilder sb = new StringBuilder();
    for (int j = i + 1; j < json.Length; j++) {
      char c = json[j];
      if (c == '\\' && j + 1 < json.Length) { sb.Append(json[++j]); continue; }
      if (c == '"') break;
      sb.Append(c);
    }
    return sb.ToString();
  }
  static string JsonEscape(string value) {
    if (string.IsNullOrEmpty(value)) return "";
    return value.Replace("\\", "\\\\").Replace("\"", "\\\"");
  }
  void WriteCors(HttpListenerContext ctx) {
    try {
      HttpListenerResponse res = ctx.Response;
      res.StatusCode = 204;
      res.AddHeader("Access-Control-Allow-Origin", "*");
      res.AddHeader("Access-Control-Allow-Methods", "GET, POST, OPTIONS");
      res.AddHeader("Access-Control-Allow-Headers", "Content-Type, X-Host-Helper-Token");
      res.ContentLength64 = 0;
      res.OutputStream.Close();
    } catch {}
  }
  void WriteJson(HttpListenerContext ctx, int status, string json) {
    try {
      byte[] bytes = Encoding.UTF8.GetBytes(json ?? "{}");
      HttpListenerResponse res = ctx.Response;
      res.StatusCode = status;
      res.ContentType = "application/json; charset=utf-8";
      res.AddHeader("Access-Control-Allow-Origin", "*");
      res.ContentLength64 = bytes.Length;
      res.OutputStream.Write(bytes, 0, bytes.Length);
      res.OutputStream.Close();
    } catch {}
  }
  void WriteBytes(HttpListenerContext ctx, string json) {
    WriteJson(ctx, 200, json);
  }
  void WriteHealth(HttpListenerContext ctx) {
    WriteBytes(ctx, HealthJson ?? "{\"ok\":true}");
  }
  void WriteCached(HttpListenerContext ctx, string path, string fallback) {
    string json = fallback;
    try {
      if (!string.IsNullOrEmpty(path) && File.Exists(path)) {
        string raw = File.ReadAllText(path);
        if (!string.IsNullOrWhiteSpace(raw)) json = raw;
      }
    } catch {}
    WriteBytes(ctx, json);
  }
  void WriteMobileDevices(HttpListenerContext ctx) {
    string json = "{\"ok\":true,\"mobile_devices\":[],\"count\":0}";
    try {
      if (!string.IsNullOrEmpty(MobileJsonPath) && File.Exists(MobileJsonPath)) {
        string raw = File.ReadAllText(MobileJsonPath);
        if (!string.IsNullOrWhiteSpace(raw)) {
          string trimmed = raw.Trim();
          if (trimmed.StartsWith("[")) json = "{\"ok\":true,\"mobile_devices\":" + trimmed + ",\"count\":0}";
          else json = trimmed;
        }
      }
    } catch {}
    WriteBytes(ctx, json);
  }
  static long JsonLong(string json, string key) {
    if (string.IsNullOrEmpty(json) || string.IsNullOrEmpty(key)) return 0;
    string needle = "\"" + key + "\"";
    int i = json.IndexOf(needle, StringComparison.OrdinalIgnoreCase);
    if (i < 0) return 0;
    i = json.IndexOf(':', i + needle.Length);
    if (i < 0) return 0;
    i++;
    while (i < json.Length && char.IsWhiteSpace(json[i])) i++;
    long n = 0;
    bool any = false;
    while (i < json.Length && char.IsDigit(json[i])) { n = n * 10 + (json[i] - '0'); i++; any = true; }
    return any ? n : 0;
  }
  static int JsonInt(string json, string key) {
    long n = JsonLong(json, key);
    if (n > int.MaxValue) return int.MaxValue;
    if (n < int.MinValue) return int.MinValue;
    return (int)n;
  }
  string FindLiveStaging(string runName, string progressJson) {
    string dest = JsonStr(progressJson ?? "", "output_path");
    if (!string.IsNullOrEmpty(dest) && dest.IndexOf("\\ib\\", StringComparison.OrdinalIgnoreCase) >= 0 && Directory.Exists(dest))
      return dest;
    string stamp = "";
    if (!string.IsNullOrEmpty(runName)) {
      Match m = Regex.Match(runName, @"(\d{8}_\d{6})$");
      if (m.Success) stamp = m.Groups[1].Value;
    }
    if (stamp.Length > 0) {
      string[] roots = new string[] { @"F:\ib", @"D:\ib", @"C:\ib", @"E:\ib" };
      for (int i = 0; i < roots.Length; i++) {
        if (!Directory.Exists(roots[i])) continue;
        try {
          string[] tails = Directory.GetDirectories(roots[i]);
          for (int t = 0; t < tails.Length; t++) {
            string cand = Path.Combine(tails[t], stamp);
            if (Directory.Exists(cand)) return cand;
          }
        } catch {}
      }
    }
    if (!string.IsNullOrEmpty(dest) && Directory.Exists(dest)) return dest;
    return "";
  }
  bool JobWasCancelled(string progressFile) {
    if (string.IsNullOrEmpty(progressFile)) return false;
    try {
      if (File.Exists(progressFile + ".cancel")) return true;
      if (!File.Exists(progressFile)) return false;
      string p = File.ReadAllText(progressFile);
      string stage = JsonStr(p, "stage");
      string item = JsonStr(p, "item");
      return stage == "cancelled" || item == "cancelled";
    } catch { return false; }
  }
  bool ResultFileReady(string resultFile) {
    if (string.IsNullOrEmpty(resultFile) || !File.Exists(resultFile)) return false;
    try {
      FileInfo fi = new FileInfo(resultFile);
      if (fi.Length < 8) return false;
      string head = "";
      using (FileStream fs = File.Open(resultFile, FileMode.Open, FileAccess.Read, FileShare.ReadWrite)) {
        byte[] buf = new byte[Math.Min(4096, (int)fi.Length)];
        int n = fs.Read(buf, 0, buf.Length);
        head = Encoding.UTF8.GetString(buf, 0, n);
      }
      if (head.IndexOf("\"ok\"", StringComparison.OrdinalIgnoreCase) < 0) return false;
      // native_ios_job / native_mtp_job write ok:false + stage_reached acquire as a
      // start placeholder. That must not look like a finished collection.
      if (head.IndexOf("\"stage_reached\":\"acquire\"", StringComparison.OrdinalIgnoreCase) >= 0) return false;
      if (head.IndexOf("\"stage_reached\": \"acquire\"", StringComparison.OrdinalIgnoreCase) >= 0) return false;
      return true;
    } catch { return false; }
  }
  bool PidStillOurs(int pid, string metaPath) {
    if (pid <= 0) return false;
    try {
      Process p = Process.GetProcessById(pid);
      if (p == null || p.HasExited) return false;
      string n = (p.ProcessName ?? "").ToLowerInvariant();
      if (n != "powershell" && n != "pwsh" && n != "python" && n != "pythonw") return false;
      if (!string.IsNullOrEmpty(metaPath) && File.Exists(metaPath)) {
        DateTime jobTime = File.GetLastWriteTime(metaPath);
        if (p.StartTime > jobTime.AddMinutes(2)) return false;
      }
      return true;
    } catch { return false; }
  }
  bool SkipLiveScanPath(string path) {
    if (string.IsNullOrEmpty(path)) return true;
    string n = path.Replace('/', '\\');
    if (n.IndexOf("\\05_Exports", StringComparison.OrdinalIgnoreCase) >= 0) return true;
    if (n.IndexOf("\\readable_artifacts", StringComparison.OrdinalIgnoreCase) >= 0) return true;
    return false;
  }
  void KickLiveScan(string path) {
    if (SkipLiveScanPath(path) || !Directory.Exists(path)) return;
    if (Interlocked.CompareExchange(ref _liveBusy, 1, 0) != 0) return;
    string scanPath = path;
    Thread th = new Thread((ThreadStart)delegate {
      try {
        int files = 0;
        long bytes = 0;
        string newest = "";
        DateTime nt = DateTime.MinValue;
        DateTime started = DateTime.UtcNow;
        foreach (string f in Directory.EnumerateFiles(scanPath, "*", SearchOption.AllDirectories)) {
          if ((DateTime.UtcNow - started).TotalSeconds > 20) break;
          files++;
          try {
            FileInfo fi = new FileInfo(f);
            if (fi.Length > 512L * 1024 * 1024) continue;
            if ((fi.Attributes & FileAttributes.ReparsePoint) != 0) continue;
            bytes += fi.Length;
            if (fi.LastWriteTime > nt) { nt = fi.LastWriteTime; newest = f; }
          } catch {}
        }
        _liveFiles = files;
        _liveBytes = bytes;
        _liveNewest = newest ?? "";
        _livePath = scanPath;
      } catch {}
      finally { Interlocked.Exchange(ref _liveBusy, 0); }
    });
    th.IsBackground = true;
    th.Name = "aetheris-live-scan";
    th.Start();
  }
  void WriteJobList(HttpListenerContext ctx) {
    try {
      List<string> parts = new List<string>();
      if (!string.IsNullOrEmpty(JobsDir) && Directory.Exists(JobsDir)) {
        foreach (string f in Directory.GetFiles(JobsDir, "*.json")) {
          string jobId = Path.GetFileNameWithoutExtension(f);
          string meta = "";
          try { meta = File.ReadAllText(f); } catch { continue; }
          int pid = JsonInt(meta, "pid");
          string resultFile = JsonStr(meta, "result_file");
          bool resultReady = ResultFileReady(resultFile);
          bool alive = PidStillOurs(pid, f);
          if (JobWasCancelled(JsonStr(meta, "progress_file")) && !resultReady) continue;
          if (resultReady) {
            string head = "";
            try { head = File.ReadAllText(resultFile); } catch { continue; }
            bool okVal = head.IndexOf("\"ok\":false", StringComparison.OrdinalIgnoreCase) < 0
              && head.IndexOf("\"ok\": false", StringComparison.OrdinalIgnoreCase) < 0;
            string doneName = JsonStr(head, "run_name");
            string doneCase = JsonStr(meta, "case_id");
            int doneFiles = JsonInt(head, "file_count");
            if (doneFiles <= 0) doneFiles = JsonInt(head, "files_seen");
            long doneBytes = JsonLong(head, "output_size");
            if (doneBytes <= 0) doneBytes = JsonLong(head, "bytes_done");
            string doneStatus = okVal ? "completed" : "failed";
            parts.Add("{\"job_id\":\"" + JsonEscape(jobId) + "\",\"status\":\"" + doneStatus + "\",\"run_name\":\"" +
              JsonEscape(doneName) + "\",\"case_id\":\"" + JsonEscape(doneCase) +
              "\",\"detail\":\"Collection finished\",\"files_seen\":" + doneFiles +
              ",\"bytes_done\":" + doneBytes + ",\"progress_pct\":" + (okVal ? "100" : "0") + "}");
            continue;
          }
          if (!alive) continue;
          string progressFile = JsonStr(meta, "progress_file");
          string detail = "";
          string runName = "";
          int files = 0;
          long bytes = 0;
          int pct = 0;
          string progJson = "";
          string item = "";
          string outputPath = "";
          if (!string.IsNullOrEmpty(progressFile) && File.Exists(progressFile)) {
            try { progJson = File.ReadAllText(progressFile); } catch { progJson = ""; }
            detail = JsonStr(progJson, "detail");
            runName = JsonStr(progJson, "run_name");
            files = JsonInt(progJson, "files_seen");
            bytes = JsonLong(progJson, "bytes_done");
            pct = JsonInt(progJson, "progress_pct");
            item = JsonStr(progJson, "item");
            outputPath = JsonStr(progJson, "output_path");
          }
          string stage = JsonStr(progJson, "stage");
          bool sealing = stage == "seal" || item == "export_packages" ||
            (!string.IsNullOrEmpty(detail) && detail.IndexOf("package", StringComparison.OrdinalIgnoreCase) >= 0);
          bool finishedProg = stage == "complete" || stage == "failed" || stage == "error" || item == "complete";
          if (!sealing && !finishedProg) {
            string staging = FindLiveStaging(runName, progJson);
            if (!SkipLiveScanPath(staging)) {
              KickLiveScan(staging);
              if (_liveFiles > files) files = _liveFiles;
              if (_liveBytes > bytes) bytes = _liveBytes;
              if (!string.IsNullOrEmpty(_liveNewest)) item = _liveNewest;
              if (!string.IsNullOrEmpty(_livePath)) outputPath = _livePath;
            }
          } else if (sealing && pct < 95) {
            pct = 100;
          }
          string caseId = JsonStr(meta, "case_id");
          parts.Add("{\"job_id\":\"" + JsonEscape(jobId) + "\",\"status\":\"running\",\"run_name\":\"" +
            JsonEscape(runName) + "\",\"case_id\":\"" + JsonEscape(caseId) + "\",\"detail\":\"" + JsonEscape(detail) +
            "\",\"item\":\"" + JsonEscape(item) + "\",\"output_path\":\"" + JsonEscape(outputPath) +
            "\",\"files_seen\":" + files + ",\"bytes_done\":" + bytes + ",\"progress_pct\":" + pct + "}");
        }
      }
      WriteBytes(ctx, "{\"ok\":true,\"jobs\":[" + string.Join(",", parts.ToArray()) + "]}");
    } catch (Exception ex) {
      WriteBytes(ctx, "{\"ok\":false,\"jobs\":[],\"error\":\"" + JsonEscape(ex.Message) + "\"}");
    }
  }
  bool SidecarAcquireAlive() {
    if (string.IsNullOrEmpty(JobsDir) || !Directory.Exists(JobsDir)) return false;
    foreach (string f in Directory.GetFiles(JobsDir, "*.json")) {
      try {
        string meta = File.ReadAllText(f);
        int pid = JsonInt(meta, "pid");
        string resultFile = JsonStr(meta, "result_file");
        if (ResultFileReady(resultFile)) continue;
        if (JobWasCancelled(JsonStr(meta, "progress_file"))) continue;
        if (PidStillOurs(pid, f)) return true;
      } catch {}
    }
    return false;
  }
  bool AnyAcquireProcessAlive() {
    try {
      ProcessStartInfo psi = new ProcessStartInfo();
      psi.FileName = "wmic.exe";
      psi.Arguments = "process get ProcessId,Name,CommandLine /FORMAT:CSV";
      psi.RedirectStandardOutput = true;
      psi.UseShellExecute = false;
      psi.CreateNoWindow = true;
      using (Process p = Process.Start(psi)) {
        if (p == null) return false;
        string all = p.StandardOutput.ReadToEnd() ?? "";
        p.WaitForExit(4000);
        string[] needles = new string[] {
          "acq_run_", "ios_usbmux_backup", "native_ios_job", "native_mtp_job", "host-mobile-acquire"
        };
        foreach (string line in all.Split(new char[] {'\n','\r'}, StringSplitOptions.RemoveEmptyEntries)) {
          string lower = line.ToLowerInvariant();
          if (lower.IndexOf("host-drive-helper") >= 0) continue;
          for (int i = 0; i < needles.Length; i++) {
            if (lower.IndexOf(needles[i]) >= 0) return true;
          }
        }
      }
    } catch {}
    return false;
  }
  void KillMatchingAcquireProcesses() {
    try {
      ProcessStartInfo psi = new ProcessStartInfo();
      psi.FileName = "powershell.exe";
      psi.Arguments = "-NoProfile -NonInteractive -WindowStyle Hidden -Command \"Get-CimInstance Win32_Process | Where-Object { $_.CommandLine -and $_.CommandLine -notmatch 'host-drive-helper' -and (($_.Name -match 'python' -and $_.CommandLine -match 'acq_run_|ios_usbmux_backup|native_ios_job|native_mtp_job|host-mobile-acquire') -or ($_.Name -match 'powershell|pwsh' -and $_.CommandLine -match 'native_ios_job|native_mtp_job|host-mobile-acquire')) } | ForEach-Object { & taskkill.exe /PID $_.ProcessId /T /F 2>$null }\"";
      psi.UseShellExecute = false;
      psi.CreateNoWindow = true;
      Process p = Process.Start(psi);
      if (p != null) p.WaitForExit(15000);
    } catch {}
  }
  void WriteCancelUsb(HttpListenerContext ctx) {
    string jobId = "";
    try {
      using (StreamReader reader = new StreamReader(ctx.Request.InputStream, Encoding.UTF8)) {
        string body = reader.ReadToEnd() ?? "";
        jobId = JsonStr(body, "job_id");
      }
    } catch {}
    List<string> stopped = new List<string>();
    try {
      if (!string.IsNullOrEmpty(JobsDir) && Directory.Exists(JobsDir)) {
        string[] files;
        if (!string.IsNullOrEmpty(jobId)) {
          string one = Path.Combine(JobsDir, jobId + ".json");
          files = File.Exists(one) ? new string[] { one } : new string[0];
        } else {
          files = Directory.GetFiles(JobsDir, "*.json");
        }
        for (int i = 0; i < files.Length; i++) {
          try {
            string f = files[i];
            string meta = File.ReadAllText(f);
            int pid = JsonInt(meta, "pid");
            string id = Path.GetFileNameWithoutExtension(f);
            string progressFile = JsonStr(meta, "progress_file");
            if (pid > 0) {
              try {
                ProcessStartInfo tk = new ProcessStartInfo();
                tk.FileName = "taskkill.exe";
                tk.Arguments = "/PID " + pid + " /T /F";
                tk.UseShellExecute = false;
                tk.CreateNoWindow = true;
                Process t = Process.Start(tk);
                if (t != null) t.WaitForExit(5000);
              } catch {}
              stopped.Add(id);
            }
            if (!string.IsNullOrEmpty(progressFile)) {
              try { File.WriteAllText(progressFile + ".cancel", "cancel"); } catch {}
              try {
                File.WriteAllText(progressFile,
                  "{\"stage\":\"cancelled\",\"item\":\"cancelled\",\"detail\":\"Stopped by examiner\",\"category\":\"Cancelled\",\"bytes_done\":0,\"files_seen\":0}");
              } catch {}
            }
          } catch {}
        }
      }
      if (string.IsNullOrEmpty(jobId)) {
        KillMatchingAcquireProcesses();
      } else {
        try {
          ProcessStartInfo psi = new ProcessStartInfo();
          psi.FileName = "powershell.exe";
          psi.Arguments = "-NoProfile -NonInteractive -WindowStyle Hidden -Command \"Get-CimInstance Win32_Process | Where-Object { $_.CommandLine -and $_.CommandLine -match [regex]::Escape('" + jobId.Replace("'", "") + "') -and $_.CommandLine -notmatch 'host-drive-helper' } | ForEach-Object { & taskkill.exe /PID $_.ProcessId /T /F 2>$null }\"";
          psi.UseShellExecute = false;
          psi.CreateNoWindow = true;
          Process p = Process.Start(psi);
          if (p != null) p.WaitForExit(15000);
        } catch {}
      }
    } catch {}
    List<string> quoted = new List<string>();
    for (int i = 0; i < stopped.Count; i++) quoted.Add("\"" + JsonEscape(stopped[i]) + "\"");
    WriteJson(ctx, 200, "{\"ok\":true,\"cancelled\":[" + string.Join(",", quoted.ToArray()) + "],\"message\":\"Host collection stopped\"}");
  }
  bool ProgressSaysFinished(string progressFile) {
    if (string.IsNullOrEmpty(progressFile) || !File.Exists(progressFile)) return false;
    try {
      string p = File.ReadAllText(progressFile);
      string stage = JsonStr(p, "stage");
      string item = JsonStr(p, "item");
      string detail = JsonStr(p, "detail");
      if (stage == "complete" || stage == "failed" || stage == "error" || item == "complete") return true;
      if (!string.IsNullOrEmpty(detail) && (
          detail.IndexOf("Collection finished", StringComparison.OrdinalIgnoreCase) >= 0 ||
          detail.IndexOf("Portable packages", StringComparison.OrdinalIgnoreCase) >= 0)) return true;
      return false;
    } catch { return false; }
  }
  string SlimCompletedPayload(string jobId, string body, bool okVal, string status) {
    string runName = JsonStr(body, "run_name");
    string exports = JsonStr(body, "exports");
    string original = JsonStr(body, "original");
    string logs = JsonStr(body, "logs");
    string hashes = JsonStr(body, "hashes");
    string caseRoot = JsonStr(body, "case_root");
    string zip = JsonStr(body, "zip");
    string pas = JsonStr(body, "pas");
    string ufd = JsonStr(body, "ufd");
    string ufdx = JsonStr(body, "ufdx");
    string osFamily = JsonStr(body, "os_family");
    string err = JsonStr(body, "error");
    int doneFiles = JsonInt(body, "file_count");
    long doneSize = JsonLong(body, "output_size");
    string resultJson = "{\"ok\":" + (okVal ? "true" : "false") +
      ",\"run_name\":\"" + JsonEscape(runName) +
      "\",\"stage_reached\":\"" + (okVal ? "complete" : status) +
      "\",\"error\":\"" + JsonEscape(err) +
      "\",\"device_profile\":{\"os_family\":\"" + JsonEscape(osFamily) + "\"}" +
      ",\"paths\":{\"exports\":\"" + JsonEscape(exports) + "\",\"original\":\"" + JsonEscape(original) +
      "\",\"logs\":\"" + JsonEscape(logs) + "\",\"hashes\":\"" + JsonEscape(hashes) +
      "\",\"case_root\":\"" + JsonEscape(caseRoot) + "\",\"run_name\":\"" + JsonEscape(runName) + "\"}" +
      ",\"export_packages\":{\"packages\":{\"zip\":\"" + JsonEscape(zip) + "\",\"pas\":\"" + JsonEscape(pas) +
      "\",\"ufd\":\"" + JsonEscape(ufd) + "\",\"ufdx\":\"" + JsonEscape(ufdx) + "\"},\"full_payload_in_zip\":true}" +
      ",\"acquisition_record\":{\"output_size\":" + doneSize + ",\"file_count\":" + doneFiles + "}" +
      ",\"verification\":{\"ok\":" + (okVal ? "true" : "false") + ",\"verified\":" + doneFiles + "}" +
      ",\"evidence_package\":{\"run_name\":\"" + JsonEscape(runName) + "\",\"extraction_data\":[],\"file_count\":" +
      doneFiles + ",\"complete\":" + (okVal ? "true" : "false") + "}}";
    return "{\"ok\":true,\"status\":\"" + status + "\",\"job_id\":\"" + JsonEscape(jobId) + "\",\"result\":" + resultJson + "}";
  }
  string CompletedJobPayload(string jobId, string resultFile) {
    string body = "";
    try { body = File.ReadAllText(resultFile); } catch { body = ""; }
    bool okVal = true;
    string status = "completed";
    if (body.IndexOf("\"ok\":false", StringComparison.OrdinalIgnoreCase) >= 0 ||
        body.IndexOf("\"ok\": false", StringComparison.OrdinalIgnoreCase) >= 0) {
      okVal = false;
      status = "failed";
    }
    long len = 0;
    try { len = new FileInfo(resultFile).Length; } catch {}
    if (len > 80000 || string.IsNullOrEmpty(body) || !body.TrimStart().StartsWith("{")) {
      return SlimCompletedPayload(jobId, body, okVal, status);
    }
    return "{\"ok\":true,\"status\":\"" + status + "\",\"job_id\":\"" + JsonEscape(jobId) +
      "\",\"result\":" + body + "}";
  }
  bool WriteJobStatus(HttpListenerContext ctx, string path, string query) {
    try {
      string jobId = "";
      if (path.StartsWith("/acquisition/job/") && path.Length > "/acquisition/job/".Length)
        jobId = Uri.UnescapeDataString(path.Substring("/acquisition/job/".Length).Trim('/'));
      if (string.IsNullOrEmpty(jobId) && !string.IsNullOrEmpty(query)) {
        int i = query.IndexOf("id=", StringComparison.OrdinalIgnoreCase);
        if (i >= 0) {
          i += 3;
          int amp = query.IndexOf('&', i);
          string raw = amp < 0 ? query.Substring(i) : query.Substring(i, amp - i);
          jobId = Uri.UnescapeDataString(raw.TrimStart('?'));
        }
      }
      if (string.IsNullOrEmpty(jobId) || string.IsNullOrEmpty(JobsDir)) return false;
      string metaPath = Path.Combine(JobsDir, jobId + ".json");
      if (!File.Exists(metaPath)) return false;
      string meta = File.ReadAllText(metaPath);
      int pid = JsonInt(meta, "pid");
      string resultFile = JsonStr(meta, "result_file");
      string progressFile = JsonStr(meta, "progress_file");
      bool resultReady = ResultFileReady(resultFile);
      bool finishedProg = ProgressSaysFinished(progressFile);
      bool alive = PidStillOurs(pid, metaPath);
      if (resultReady) {
        WriteBytes(ctx, CompletedJobPayload(jobId, resultFile));
        return true;
      }
      string runName = "";
      if (alive && !finishedProg) {
        string progHead = "";
        if (!string.IsNullOrEmpty(progressFile) && File.Exists(progressFile)) {
          try { progHead = File.ReadAllText(progressFile); } catch { progHead = ""; }
        }
        runName = JsonStr(progHead, "run_name");
        int fileCount = JsonInt(progHead, "file_count");
        if (fileCount <= 0) fileCount = JsonInt(progHead, "files_seen");
        long outputSize = JsonLong(progHead, "output_size");
        if (outputSize <= 0) outputSize = JsonLong(progHead, "bytes_done");
        string detail = JsonStr(progHead, "detail");
        int pct = JsonInt(progHead, "progress_pct");
        string item = JsonStr(progHead, "item");
        string outputPath = JsonStr(progHead, "output_path");
        string casePath = JsonStr(progHead, "case_path");
        string mediaPath = JsonStr(progHead, "media_path");
        string jobStage = JsonStr(progHead, "stage");
        bool sealingJob = jobStage == "seal" || item == "export_packages" ||
          (!string.IsNullOrEmpty(detail) && detail.IndexOf("package", StringComparison.OrdinalIgnoreCase) >= 0);
        if (!sealingJob) {
          string staging = FindLiveStaging(runName, progHead);
          if (!SkipLiveScanPath(staging)) {
            KickLiveScan(staging);
            if (_liveFiles > fileCount) fileCount = _liveFiles;
            if (_liveBytes > outputSize) outputSize = _liveBytes;
            if (!string.IsNullOrEmpty(_liveNewest)) item = _liveNewest;
            if (!string.IsNullOrEmpty(_livePath)) outputPath = _livePath;
          }
        } else if (sealingJob && pct < 95) {
          pct = 100;
        }
        string jsonRun = "{\"ok\":true,\"status\":\"running\",\"job_id\":\"" + JsonEscape(jobId) +
          "\",\"detail\":\"" + JsonEscape(detail) + "\",\"progress_pct\":" + pct +
          ",\"files_seen\":" + fileCount + ",\"bytes_done\":" + outputSize +
          ",\"item\":\"" + JsonEscape(item) + "\",\"output_path\":\"" + JsonEscape(outputPath) +
          "\",\"case_path\":\"" + JsonEscape(casePath) + "\",\"media_path\":\"" + JsonEscape(mediaPath) +
          "\",\"result\":{\"ok\":false,\"run_name\":\"" + JsonEscape(runName) +
          "\",\"stage_reached\":\"acquire\",\"detail\":\"" + JsonEscape(detail) +
          "\",\"progress_pct\":" + pct + ",\"item\":\"" + JsonEscape(item) +
          "\",\"output_path\":\"" + JsonEscape(outputPath) +
          "\",\"acquisition_record\":{\"output_size\":" + outputSize + ",\"file_count\":" + fileCount + "}}}";
        WriteBytes(ctx, jsonRun);
        return true;
      }
      if (finishedProg && !resultReady) {
        string progHead = "";
        if (!string.IsNullOrEmpty(progressFile) && File.Exists(progressFile)) {
          try { progHead = File.ReadAllText(progressFile); } catch { progHead = ""; }
        }
        runName = JsonStr(progHead, "run_name");
        int fileCount = JsonInt(progHead, "file_count");
        if (fileCount <= 0) fileCount = JsonInt(progHead, "files_seen");
        long outputSize = JsonLong(progHead, "output_size");
        if (outputSize <= 0) outputSize = JsonLong(progHead, "bytes_done");
        string detail = JsonStr(progHead, "detail");
        string jobStage = JsonStr(progHead, "stage");
        bool failedProg = jobStage == "failed" || jobStage == "error";
        string doneStatus = failedProg ? "failed" : "completed";
        string jsonFin = "{\"ok\":true,\"status\":\"" + doneStatus + "\",\"job_id\":\"" + JsonEscape(jobId) +
          "\",\"detail\":\"" + JsonEscape(detail) + "\",\"progress_pct\":100,\"files_seen\":" + fileCount +
          ",\"bytes_done\":" + outputSize + ",\"item\":\"complete\",\"result\":{\"ok\":" + (failedProg ? "false" : "true") +
          ",\"run_name\":\"" + JsonEscape(runName) + "\",\"stage_reached\":\"" + (failedProg ? "failed" : "complete") +
          "\",\"detail\":\"" + JsonEscape(detail) +
          "\",\"acquisition_record\":{\"output_size\":" + outputSize + ",\"file_count\":" + fileCount +
          "},\"evidence_package\":{\"run_name\":\"" + JsonEscape(runName) +
          "\",\"extraction_data\":[],\"file_count\":" + fileCount + ",\"complete\":" + (failedProg ? "false" : "true") + "}}}";
        WriteBytes(ctx, jsonFin);
        return true;
      }
      if (JobWasCancelled(progressFile) && !resultReady) {
        string jsonCancel = "{\"ok\":true,\"status\":\"cancelled\",\"job_id\":\"" + JsonEscape(jobId) +
          "\",\"result\":{\"ok\":false,\"run_name\":\"\",\"stage_reached\":\"cancelled\",\"error\":\"Cancelled by examiner\",\"errors\":[\"Cancelled by examiner\"],\"paths\":{},\"acquisition_record\":{\"output_size\":0,\"file_count\":0}}}";
        WriteBytes(ctx, jsonCancel);
        return true;
      }
      string status = "running";
      bool okVal = true;
      string err = "";
      if (resultReady) {
        string body = "";
        try { body = File.ReadAllText(resultFile); } catch { body = ""; }
        if (string.IsNullOrEmpty(body)) {
          try {
            using (FileStream fs = File.OpenRead(resultFile)) {
              byte[] buf = new byte[Math.Min(65536, (int)Math.Max(1, fs.Length))];
              int n = fs.Read(buf, 0, buf.Length);
              body = Encoding.UTF8.GetString(buf, 0, n);
            }
          } catch { body = ""; }
        }
        if (body.IndexOf("\"ok\":false", StringComparison.OrdinalIgnoreCase) >= 0 ||
            body.IndexOf("\"ok\": false", StringComparison.OrdinalIgnoreCase) >= 0) {
          okVal = false;
          status = "failed";
        } else {
          status = "completed";
        }
        if (!string.IsNullOrEmpty(body) && body.TrimStart().StartsWith("{")) {
          string jsonDone = "{\"ok\":true,\"status\":\"" + status + "\",\"job_id\":\"" + JsonEscape(jobId) +
            "\",\"result\":" + body + "}";
          WriteBytes(ctx, jsonDone);
          return true;
        }
        runName = JsonStr(body, "run_name");
        err = JsonStr(body, "error");
        int doneFiles = JsonInt(body, "file_count");
        long doneSize = JsonLong(body, "output_size");
        string resultJson = "{\"ok\":" + (okVal ? "true" : "false") +
          ",\"run_name\":\"" + JsonEscape(runName) +
          "\",\"stage_reached\":\"" + status + "\",\"error\":\"" + JsonEscape(err) +
          "\",\"errors\":" + (okVal || string.IsNullOrEmpty(err) ? "[]" : ("[\"" + JsonEscape(err) + "\"]")) +
          ",\"method_decision\":{\"selected\":\"logical\",\"rationale\":\"Android MTP file-transfer logical copy of shared storage.\"}" +
          ",\"acquisition_record\":{\"output_size\":" + doneSize + ",\"file_count\":" + doneFiles + "}" +
          ",\"evidence_package\":{\"run_name\":\"" + JsonEscape(runName) + "\",\"extraction_data\":[],\"file_count\":" + doneFiles + ",\"complete\":" + (okVal ? "true" : "false") + "}}";
        string jsonDone2 = "{\"ok\":true,\"status\":\"" + status + "\",\"job_id\":\"" + JsonEscape(jobId) +
          "\",\"result\":" + resultJson + "}";
        WriteBytes(ctx, jsonDone2);
        return true;
      }
      status = "failed";
      okVal = false;
      err = "Acquire process exited without result";
      string errFile = JsonStr(meta, "err_file");
      if (!string.IsNullOrEmpty(errFile) && File.Exists(errFile)) {
        try {
          string tail = File.ReadAllText(errFile);
          if (!string.IsNullOrEmpty(tail)) {
            if (tail.Length > 500) tail = tail.Substring(0, 500);
            err = tail.Replace("\r", " ").Replace("\n", " ").Trim();
          }
        } catch {}
      }
      string resultJsonRun = "{\"ok\":" + (okVal ? "true" : "false") +
        ",\"run_name\":\"" + JsonEscape(runName) +
        "\",\"stage_reached\":\"" + status + "\",\"error\":\"" + JsonEscape(err) + "\"}";
      string json = "{\"ok\":true,\"status\":\"" + status + "\",\"job_id\":\"" + JsonEscape(jobId) +
        "\",\"result\":" + resultJsonRun + "}";
      WriteBytes(ctx, json);
      return true;
    } catch {
      return false;
    }
  }
  void WriteNativeUsbRun(HttpListenerContext ctx, string query) {
    try {
      string body = "";
      using (StreamReader reader = new StreamReader(ctx.Request.InputStream, Encoding.UTF8)) {
        body = reader.ReadToEnd() ?? "";
      }
      bool ios = query.IndexOf("native=ios", StringComparison.OrdinalIgnoreCase) >= 0;
      string script = ios ? NativeIosJobScript : NativeMtpJobScript;
      string via = ios ? "native_ios" : "native_mtp";
      if (string.IsNullOrEmpty(script) || !File.Exists(script)) {
        WriteBytes(ctx, "{\"ok\":false,\"error\":\"" + via + " job script missing\"}");
        return;
      }
      string stamp = Guid.NewGuid().ToString("N");
      string tmp = Path.GetTempPath();
      if (string.IsNullOrEmpty(JobsDir)) JobsDir = Path.Combine(tmp, "aetheris_acq_jobs");
      Directory.CreateDirectory(JobsDir);
      if (SidecarAcquireAlive() || AnyAcquireProcessAlive()) {
        WriteJson(ctx, 409, "{\"ok\":false,\"error\":\"Another USB collection is already running. Stop it, wait for it to finish, or register an existing backup folder for forensic analysis.\",\"busy\":true}");
        return;
      }
      string payloadFile = Path.Combine(tmp, (ios ? "acq_ios_" : "acq_mtp_") + stamp + ".json");
      string resultFile = Path.Combine(tmp, "acq_result_" + stamp + ".json");
      string progressFile = JsonStr(body, "progress_file");
      if (string.IsNullOrEmpty(progressFile))
        progressFile = Path.Combine(tmp, "acq_progress_" + stamp + ".json");
      string caseId = JsonStr(body, "case_id");
      if (body.IndexOf("\"progress_file\"", StringComparison.OrdinalIgnoreCase) < 0 && body.TrimEnd().EndsWith("}")) {
        string trimmed = body.TrimEnd();
        body = trimmed.Substring(0, trimmed.Length - 1) + ",\"progress_file\":\"" + JsonEscape(progressFile) + "\"}";
      }
      File.WriteAllText(payloadFile, body, new UTF8Encoding(false));
      try {
        File.WriteAllText(progressFile,
          "{\"stage\":\"acquire\",\"item\":\"starting\",\"detail\":\"Starting collection on this PC. Keep the phone unlocked.\",\"category\":\"Collecting\",\"bytes_done\":0,\"files_seen\":0}",
          new UTF8Encoding(false));
      } catch {}
      string outFile = Path.Combine(tmp, (ios ? "acq_ios_" : "acq_mtp_") + stamp + ".out");
      string errFile = Path.Combine(tmp, (ios ? "acq_ios_" : "acq_mtp_") + stamp + ".err");
      ProcessStartInfo psi = new ProcessStartInfo();
      psi.FileName = "powershell.exe";
      psi.Arguments = "-STA -NoProfile -ExecutionPolicy Bypass -File \"" + script +
        "\" -PayloadFile \"" + payloadFile + "\" -ResultFile \"" + resultFile + "\"";
      psi.WorkingDirectory = string.IsNullOrEmpty(RootPath) ? tmp : RootPath;
      psi.UseShellExecute = false;
      psi.CreateNoWindow = true;
      psi.RedirectStandardOutput = true;
      psi.RedirectStandardError = true;
      Process proc = Process.Start(psi);
      int pid = proc != null ? proc.Id : 0;
      if (proc != null) {
        string capturedOut = outFile;
        string capturedErr = errFile;
        proc.OutputDataReceived += delegate(object sender, DataReceivedEventArgs e) {
          if (e == null || string.IsNullOrEmpty(e.Data)) return;
          try { File.AppendAllText(capturedOut, e.Data + Environment.NewLine); } catch {}
        };
        proc.ErrorDataReceived += delegate(object sender, DataReceivedEventArgs e) {
          if (e == null || string.IsNullOrEmpty(e.Data)) return;
          try { File.AppendAllText(capturedErr, e.Data + Environment.NewLine); } catch {}
        };
        try { proc.BeginOutputReadLine(); } catch {}
        try { proc.BeginErrorReadLine(); } catch {}
      }
      string meta = "{\"pid\":" + pid + ",\"result_file\":\"" + JsonEscape(resultFile) +
        "\",\"progress_file\":\"" + JsonEscape(progressFile) + "\",\"err_file\":\"" + JsonEscape(errFile) +
        "\",\"status\":\"running\",\"case_id\":\"" + JsonEscape(caseId) + "\"}";
      File.WriteAllText(Path.Combine(JobsDir, stamp + ".json"), meta, new UTF8Encoding(false));
      string json = "{\"ok\":true,\"async\":true,\"job_id\":\"" + stamp +
        "\",\"status\":\"running\",\"busy\":true,\"via\":\"" + via + "\"}";
      byte[] bytes = Encoding.UTF8.GetBytes(json);
      HttpListenerResponse res = ctx.Response;
      res.StatusCode = 202;
      res.ContentType = "application/json; charset=utf-8";
      res.AddHeader("Access-Control-Allow-Origin", "*");
      res.ContentLength64 = bytes.Length;
      res.OutputStream.Write(bytes, 0, bytes.Length);
      res.OutputStream.Close();
    } catch (Exception ex) {
      try {
        WriteBytes(ctx, "{\"ok\":false,\"error\":\"" + JsonEscape(ex.Message) + "\"}");
      } catch {}
    }
  }
  void WriteNativePreview(HttpListenerContext ctx) {
    try {
      string body = "";
      using (StreamReader reader = new StreamReader(ctx.Request.InputStream, Encoding.UTF8)) {
        body = reader.ReadToEnd() ?? "";
      }
      string adapter = JsonStr(body, "adapter");
      string deviceId = JsonStr(body, "device_id");
      string label = JsonStr(body, "label");
      if (string.IsNullOrEmpty(label)) label = JsonStr(body, "device_name");
      if (string.IsNullOrEmpty(label)) label = deviceId;
      string os = "android";
      if (adapter.IndexOf("ios", StringComparison.OrdinalIgnoreCase) >= 0) os = "ios";
      if (label.IndexOf("iPhone", StringComparison.OrdinalIgnoreCase) >= 0 ||
          label.IndexOf("iPad", StringComparison.OrdinalIgnoreCase) >= 0 ||
          label.IndexOf("Apple", StringComparison.OrdinalIgnoreCase) >= 0) os = "ios";
      else if (label.IndexOf("Android", StringComparison.OrdinalIgnoreCase) >= 0 ||
               label.IndexOf("Samsung", StringComparison.OrdinalIgnoreCase) >= 0 ||
               label.IndexOf("Galaxy", StringComparison.OrdinalIgnoreCase) >= 0) os = "android";
      bool logicalOnly = adapter.IndexOf("mtp", StringComparison.OrdinalIgnoreCase) >= 0;
      string methods = os == "ios" ? "[\"backup\",\"advanced_logical\",\"logical\"]" : "[\"logical\",\"advanced_logical\",\"backup\",\"file_system\",\"full_file_system\"]";
      string manufacturer = os == "ios" ? "Apple" : (label.IndexOf("Galaxy", StringComparison.OrdinalIgnoreCase) >= 0 || label.IndexOf("Samsung", StringComparison.OrdinalIgnoreCase) >= 0 ? "Samsung" : "");
      string mode = logicalOnly ? "mtp" : "usb";
      string lockState = logicalOnly ? "unlocked_for_mtp" : "unknown";
      string prep = os == "ios" ? "Tap Trust This Computer if prompted." : "Use File transfer / MTP if the phone asks.";
      string obs2 = logicalOnly ? "MTP collection of shared storage, recycle-bin folders and chat media. Enable USB debugging for ADB backup of app databases." : "Host USB collection via the HostDrive helper.";
      string json = "{\"ok\":true,\"device_profile\":{\"manufacturer\":\"" + JsonEscape(manufacturer) +
        "\",\"model\":\"" + JsonEscape(label) + "\",\"device_label\":\"" + JsonEscape(label) +
        "\",\"chipset\":\"\",\"serial\":\"" + JsonEscape(deviceId) + "\",\"imei\":\"\",\"udid\":\"" +
        (os == "ios" ? JsonEscape(deviceId) : "") +
        "\",\"os_family\":\"" + os + "\",\"os_version\":\"\",\"security_patch_level\":\"\",\"build_id\":\"\",\"lock_state\":\"" + lockState + "\",\"encryption_state\":\"unknown\",\"connection_mode\":\"" +
        mode + "\",\"usb_debugging_authorized\":" + (adapter == "android_adb" ? "true" : "false") +
        ",\"pairing_trusted\":" + (os == "ios" ? "true" : "false") +
        ",\"developer_mode\":false,\"rooted_or_jailbroken\":null,\"battery_percent\":null,\"network_isolated\":null,\"sim_present\":null,\"iccid\":\"\",\"imsi\":\"\",\"sd_card_present\":null,\"sd_card_identifier\":\"\",\"tool_version\":\"aetheris-acquire/host-helper\",\"license_entitlements\":[],\"required_cable\":\"USB data cable\",\"unknown_fields\":[],\"observations\":[\"Detected on the examiner Windows host over USB (no extra adapter).\",\"" +
        obs2 + "\"]},\"capability\":{\"capability_label\":\"SUPPORTED_DIRECT_LOGICAL\",\"supported_methods\":" + methods +
        ",\"blocked_methods\":{},\"warnings\":[],\"preparation_steps\":[\"Keep the phone unlocked and the data cable seated.\",\"" +
        prep + "\"]},\"preparation_steps\":[\"Keep the phone unlocked and the data cable seated.\",\"" +
        prep + "\"],\"method_profiles\":{}}";
      byte[] bytes = Encoding.UTF8.GetBytes(json);
      HttpListenerResponse res = ctx.Response;
      res.StatusCode = 200;
      res.ContentType = "application/json; charset=utf-8";
      res.AddHeader("Access-Control-Allow-Origin", "*");
      res.ContentLength64 = bytes.Length;
      res.OutputStream.Write(bytes, 0, bytes.Length);
      res.OutputStream.Close();
    } catch {
      try {
        byte[] bytes = Encoding.UTF8.GetBytes("{\"ok\":true,\"device_profile\":{\"os_family\":\"android\",\"model\":\"Android phone\",\"device_label\":\"Android phone\",\"serial\":\"\",\"connection_mode\":\"mtp\",\"required_cable\":\"USB data cable\",\"observations\":[\"Detected on the examiner Windows host over USB (no extra adapter).\"]},\"capability\":{\"capability_label\":\"SUPPORTED_DIRECT_LOGICAL\",\"supported_methods\":[\"logical\",\"advanced_logical\",\"backup\",\"file_system\",\"full_file_system\"],\"blocked_methods\":{},\"warnings\":[],\"preparation_steps\":[\"Keep the phone unlocked and the data cable seated.\"]},\"preparation_steps\":[\"Keep the phone unlocked and the data cable seated.\"],\"method_profiles\":{}}");
        HttpListenerResponse res = ctx.Response;
        res.StatusCode = 200;
        res.ContentType = "application/json; charset=utf-8";
        res.AddHeader("Access-Control-Allow-Origin", "*");
        res.ContentLength64 = bytes.Length;
        res.OutputStream.Write(bytes, 0, bytes.Length);
        res.OutputStream.Close();
      } catch {}
    }
  }
  public HttpListenerContext Dequeue(int timeoutMs) {
    HttpListenerContext ctx;
    if (Queue.TryTake(out ctx, timeoutMs)) return ctx;
    return null;
  }
  public void Stop() {
    _stop = true;
    try { if (_listener != null) _listener.Stop(); } catch {}
  }
}
"@

$dispatcher = New-Object AetherisHelperDispatcher
$dispatcher.HealthJson = (@{
    ok                  = $true
    service             = "host-drive-helper"
    port                = $Port
    bind_host           = $BindHost
    helper_version      = $script:HelperVersion
    helper_pid          = $PID
    helper_script       = $PSCommandPath
    root                = $root
    job_script          = $refreshJobScript
    job_script_version  = (Get-JobScriptVersion)
    started_utc         = $script:HelperStartedUtc
} | ConvertTo-Json -Compress)
$dispatcher.AdaptersJsonPath = $script:AdaptersCacheFile
$dispatcher.DevicesJsonPath = $script:AcqDevicesCacheFile
$dispatcher.MobileJsonPath = $script:DeviceCacheFile
$dispatcher.RootPath = $root
$dispatcher.NativeMtpJobScript = Join-Path $root "scripts\native_mtp_job.ps1"
$dispatcher.NativeIosJobScript = Join-Path $root "scripts\native_ios_job.ps1"
$dispatcher.JobsDir = Join-Path $env:TEMP "aetheris_acq_jobs"
$dispatcher.Start($listener)

Write-Host "Host drive helper listening on $listenPrefix"
Write-Host "Endpoints: GET /health, GET /drives, GET /mobile-devices, GET /acquisition/adapters, GET /acquisition/devices, GET /acquisition/job, POST /acquisition/run, POST /acquisition/cancel, POST /acquisition/remove, POST /acquire, POST /refresh-drive-mounts, GET /refresh-drive-mounts, POST /resolve-folder, POST /list-dir"
Write-Host "Project root: $root"
Write-Host "Press Ctrl+C to stop."

try {
    while ($listener.IsListening) {
        $context = $dispatcher.Dequeue(500)
        if ($null -eq $context) { continue }
        try {
            Handle-Request -Context $context
        }
        catch {
            try {
                Write-JsonResponse -Response $context.Response -StatusCode 500 -Body @{
                    ok    = $false
                    error = $_.Exception.Message
                }
            }
            catch {
                # Response may already be closed.
            }
        }
    }
}
finally {
    try { $dispatcher.Stop() } catch {}
    try { $listener.Close() } catch {}
}
