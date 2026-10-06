# Mobile live/logical acquisition helpers for host-drive-helper.ps1
# Creates D:\forensic-mobile-acquisitions\{job_id}\ then best-effort extract + zip image package.

function Get-MobileAcquisitionRoot {
    if ($env:MOBILE_ACQUISITION_ROOT -and $env:MOBILE_ACQUISITION_ROOT.Trim()) {
        return $env:MOBILE_ACQUISITION_ROOT.Trim().TrimEnd('\', '/')
    }
    # Use the roomiest local volume rather than the first existing D:/E:/C:.
    # Large iPhone backups can exceed 100 GiB; selecting a nearly-full drive
    # here forces temporary F:\ib staging and a later cross-volume failure.
    $ranked = @()
    foreach ($letter in @('F', 'D', 'E', 'C')) {
        if (-not (Test-Path -LiteralPath "${letter}:\")) { continue }
        try {
            $free = [int64](Get-PSDrive -Name $letter -PSProvider FileSystem -ErrorAction Stop).Free
            $ranked += [pscustomobject]@{ Letter = $letter; Free = $free }
        } catch { }
    }
    $best = $ranked | Sort-Object Free -Descending | Select-Object -First 1
    if ($best) { return ($best.Letter + ":\forensic-mobile-acquisitions") }
    return (Join-Path $env:USERPROFILE "forensic-mobile-acquisitions")
}

function Get-RepoRoot {
    if ($script:RepoRoot -and (Test-Path -LiteralPath $script:RepoRoot)) { return $script:RepoRoot }
    # host-mobile-acquire.ps1 lives in <repo>/scripts
    $here = $PSScriptRoot
    if (-not $here) { $here = Split-Path -Parent $MyInvocation.MyCommand.Path }
    $script:RepoRoot = Split-Path -Parent $here
    return $script:RepoRoot
}

function Find-IosKitPython {
    $repo = Get-RepoRoot
    $kit = Join-Path $repo "tools\host-python\Scripts\python.exe"
    if (Test-Path -LiteralPath $kit) {
        $script:CachedKitPython = $kit
        return $kit
    }
    return Find-KitPython
}

function Find-KitPython {
    if ($script:CachedKitPython -and (Test-Path -LiteralPath $script:CachedKitPython)) {
        return $script:CachedKitPython
    }
    $repo = Get-RepoRoot
    foreach ($c in @(
        (Join-Path $repo "tools\host-python\Scripts\python.exe"),
        (Join-Path $repo "backend\.venv\Scripts\python.exe"),
        (Join-Path $repo ".venv\Scripts\python.exe")
    )) {
        if (-not (Test-Path -LiteralPath $c)) { continue }
        if ($c -match '(?i)WindowsApps') { continue }
        try {
            $tag = [guid]::NewGuid().ToString("N")
            $out = Join-Path $env:TEMP ("aetheris_pyok_" + $tag + ".out")
            $err = Join-Path $env:TEMP ("aetheris_pyok_" + $tag + ".err")
            $proc = Start-Process -FilePath $c -ArgumentList @("-c", "print(1)") -PassThru -WindowStyle Hidden `
                -RedirectStandardOutput $out -RedirectStandardError $err
            if (-not $proc.WaitForExit(2500)) { try { $proc.Kill() } catch {}; Remove-Item $out, $err -Force -ErrorAction SilentlyContinue; continue }
            $ok = ($proc.ExitCode -eq 0)
            Remove-Item $out, $err -Force -ErrorAction SilentlyContinue
            if ($ok) { $script:CachedKitPython = $c; return $c }
        } catch {}
    }
    foreach ($name in @("python", "python3", "py")) {
        $cmd = Get-Command $name -ErrorAction SilentlyContinue
        if (-not $cmd -or -not $cmd.Source) { continue }
        if ($cmd.Source -match '(?i)WindowsApps') { continue }
        $exe = $cmd.Source
        if ($name -eq "py") {
            try {
                $resolved = & $exe -3 -c "import sys; print(sys.executable)" 2>$null
                if ($resolved) { $exe = [string]$resolved.Trim() }
            } catch { continue }
        }
        if ($exe -and (Test-Path -LiteralPath $exe)) { $script:CachedKitPython = $exe; return $exe }
    }
    return $null
}

function Get-KitPythonPathEnv {
    $repo = Get-RepoRoot
    $parts = @(
        (Join-Path $repo "tools\host-python\Lib\site-packages"),
        (Join-Path $repo "backend")
    )
    return ($parts -join ";")
}

function Find-HostTool {
    param([string[]]$Names, [string[]]$ExtraPaths = @())
    $repoTools = Join-Path (Get-RepoRoot) "tools\libimobiledevice"
    $bundled = @()
    foreach ($name in $Names) {
        $bundled += (Join-Path $repoTools $name)
    }
    $allExtra = @($bundled) + @($ExtraPaths)
    foreach ($name in $Names) {
        $cmd = Get-Command $name -ErrorAction SilentlyContinue
        if ($cmd -and $cmd.Source) { return $cmd.Source }
        # where.exe prints "INFO: Could not find..." to stderr; never let that stop the helper.
        $where = cmd.exe /c "where $name 2>nul" | Select-Object -First 1
        if ($where -and (Test-Path -LiteralPath $where)) { return $where }
    }
    foreach ($path in $allExtra) {
        if ($path -and (Test-Path -LiteralPath $path)) { return $path }
    }
    return $null
}

function Test-AppleMobileDeviceSupport {
    $paths = @(
        "C:\Program Files\Common Files\Apple\Mobile Device Support",
        "C:\Program Files (x86)\Common Files\Apple\Mobile Device Support",
        "C:\Program Files\Apple\Apple Mobile Device Support",
        "C:\Program Files (x86)\Apple\Apple Mobile Device Support"
    )
    foreach ($p in $paths) {
        if (Test-Path -LiteralPath $p) { return $true }
    }
    $svc = Get-Service -ErrorAction SilentlyContinue | Where-Object {
        $_.Name -match 'AppleMobileDevice' -or
        $_.DisplayName -match 'Apple Mobile Device' -or
        $_.DisplayName -match 'Apple Mobile Device Service'
    } | Select-Object -First 1
    if ($svc) { return $true }
    try {
        $pnp = Get-PnpDevice -PresentOnly -ErrorAction SilentlyContinue |
            Where-Object { $_.FriendlyName -match '(?i)Apple Mobile Device USB' } |
            Select-Object -First 1
        if ($pnp) { return $true }
    } catch { }
    return $false
}

function Get-FolderLiveStats {
    param([string]$Path)
    $out = @{ files = [int64]0; bytes = [int64]0; newest = "" }
    if (-not $Path -or -not (Test-Path -LiteralPath $Path)) { return $out }
    try {
        $n = [int64]0
        $b = [int64]0
        $newest = ""
        $nt = [datetime]::MinValue
        foreach ($f in [IO.Directory]::EnumerateFiles($Path, "*", [IO.SearchOption]::AllDirectories)) {
            $n++
            try {
                $fi = New-Object IO.FileInfo $f
                $b += [int64]$fi.Length
                if ($fi.LastWriteTime -gt $nt) {
                    $nt = $fi.LastWriteTime
                    $newest = $f
                }
            } catch {}
        }
        $out.files = $n
        $out.bytes = $b
        $out.newest = $newest
    } catch {}
    return $out
}

function Get-IosStagingDrive {
    <#
    Pick a host volume that can hold an Advanced Logical (~80 GiB).
    E: filled on 2026-09-20 and pymobiledevice3 then looked like Manifest-missing.
    #>
    param([int64]$MinFreeBytes = 85899345920)
    $ranked = New-Object System.Collections.Generic.List[object]
    foreach ($letter in @("F", "D", "C", "E")) {
        if (-not (Test-Path -LiteralPath "${letter}:\")) { continue }
        $free = [int64]-1
        try { $free = [int64](Get-PSDrive -Name $letter -PSProvider FileSystem -ErrorAction Stop).Free } catch { continue }
        $ranked.Add([pscustomobject]@{ Letter = $letter; Free = $free }) | Out-Null
    }
    $fit = $ranked | Where-Object { $_.Free -ge $MinFreeBytes } | Sort-Object Free -Descending | Select-Object -First 1
    if ($fit) { return $fit }
    return $null
}


function Get-IosDiskSizing {
    param([string]$Udid, [string]$IdeviceInfo = "")
    $fallback = [int64](80GB)
    $reserve = [int64](12GB)
    $used = [int64]0
    $capacity = [int64]0
    $available = [int64]0
    if ($IdeviceInfo -and $Udid) {
        try {
            $raw = & $IdeviceInfo -u $Udid -q com.apple.disk_usage 2>$null | Out-String
            foreach ($line in ($raw -split "`r?`n")) {
                if ($line -match '^\s*TotalDataCapacity\s*:\s*(\d+)') { $capacity = [int64]$Matches[1] }
                elseif ($line -match '^\s*TotalDataAvailable\s*:\s*(\d+)') { $available = [int64]$Matches[1] }
            }
        } catch { }
    }
    if ($capacity -gt 0 -and $available -ge 0 -and $available -le $capacity) {
        $used = $capacity - $available
    }
    if ($used -gt 0) {
        $reserve = [Math]::Max([int64](12GB), [int64]($used * 0.10))
    }
    $required = [Math]::Max($fallback, $used + $reserve)
    return @{ used = $used; capacity = $capacity; available = $available; reserve = $reserve; required = $required }
}

function Test-IosBackupComplete {
    param([Parameter(Mandatory = $true)][string]$Path)
    if (-not $Path -or -not (Test-Path -LiteralPath $Path)) { return $false }
    $db = Join-Path $Path "Manifest.db"
    if (Test-Path -LiteralPath $db) {
        try { if ((Get-Item -LiteralPath $db).Length -gt 64) { return $true } } catch { }
    }
    $plist = Join-Path $Path "Manifest.plist"
    if (Test-Path -LiteralPath $plist) {
        try { if ((Get-Item -LiteralPath $plist).Length -gt 64) { return $true } } catch { }
    }
    return $false
}

function Find-ExistingIosBackupForUdid {
    param(
        [Parameter(Mandatory = $true)][string]$Udid,
        [string]$PreferUnder = ""
    )
    $candidates = New-Object System.Collections.Generic.List[string]
    if ($PreferUnder) {
        $candidates.Add((Join-Path $PreferUnder $Udid)) | Out-Null
        $candidates.Add((Join-Path $PreferUnder "ios_image\$Udid")) | Out-Null
    }
    foreach ($letter in @("F", "D", "C", "E")) {
        $ib = "${letter}:\ib"
        if (-not (Test-Path -LiteralPath $ib)) { continue }
        Get-ChildItem -LiteralPath $ib -Directory -ErrorAction SilentlyContinue | ForEach-Object {
            $candidates.Add((Join-Path $_.FullName $Udid)) | Out-Null
            $candidates.Add($_.FullName) | Out-Null
            Get-ChildItem -LiteralPath $_.FullName -Directory -ErrorAction SilentlyContinue | ForEach-Object {
                if ($_.Name -match '_afc$') { return }
                $candidates.Add((Join-Path $_.FullName $Udid)) | Out-Null
                $candidates.Add($_.FullName) | Out-Null
            }
        }
    }
    $acqRoot = Get-MobileAcquisitionRoot
    if (Test-Path -LiteralPath $acqRoot) {
        Get-ChildItem -LiteralPath $acqRoot -Directory -ErrorAction SilentlyContinue | ForEach-Object {
            $candidates.Add((Join-Path $_.FullName "ios_image\$Udid")) | Out-Null
            $candidates.Add((Join-Path $_.FullName $Udid)) | Out-Null
        }
    }
    # Standard iTunes backup locations
    $candidates.Add((Join-Path $env:USERPROFILE "Apple\MobileSync\Backup\$Udid")) | Out-Null
    $candidates.Add((Join-Path $env:APPDATA "Apple Computer\MobileSync\Backup\$Udid")) | Out-Null

    $best = $null
    $bestFiles = 0
    foreach ($path in ($candidates | Select-Object -Unique)) {
        if (-not $path) { continue }
        if (-not (Test-IosBackupComplete -Path $path)) { continue }
        $count = @(Get-ChildItem -LiteralPath $path -Recurse -File -ErrorAction SilentlyContinue).Count
        if ($count -gt $bestFiles) {
            $best = $path
            $bestFiles = $count
        }
    }
    if ($best) {
        return @{ path = $best; files = $bestFiles }
    }
    return $null
}

function Link-IosBackupIntoJob {
    param(
        [Parameter(Mandatory = $true)][string]$SourceBackup,
        [Parameter(Mandatory = $true)][string]$DestBackup,
        [string]$LogPath = ""
    )
    if (-not (Test-Path -LiteralPath $SourceBackup)) { return $false }
    $parent = Split-Path -Parent $DestBackup
    New-Item -ItemType Directory -Force -Path $parent | Out-Null

    # Current-run X:\ib is only a short-path staging namespace.  When the case
    # is on the same volume, rename the backup into 02_Original_Extraction.
    # When it is on another volume, do NOT duplicate 100+ GiB with robocopy;
    # relocate the staging tree on the same source volume to a stable evidence
    # payload directory and junction the case path to it.  ZIP/hash/inventory
    # walkers follow this junction in V20, so the payload is still complete.
    if ($SourceBackup -match '^[A-Za-z]:\\ib\\') {
        $srcRoot = [IO.Path]::GetPathRoot($SourceBackup)
        $dstRoot = [IO.Path]::GetPathRoot($DestBackup)
        if ($srcRoot -and $dstRoot -and ($srcRoot -ieq $dstRoot)) {
            if (Test-Path -LiteralPath $DestBackup) {
                Remove-Item -LiteralPath $DestBackup -Recurse -Force -ErrorAction SilentlyContinue
            }
            try {
                Move-Item -LiteralPath $SourceBackup -Destination $DestBackup -Force -ErrorAction Stop
                if ($LogPath) { Write-AcquireLog $LogPath ("Committed staged iOS backup into case: {0}" -f $DestBackup) }
                return (Test-IosBackupComplete -Path $DestBackup)
            } catch {
                if ($LogPath) { Write-AcquireLog $LogPath ("Same-volume iOS backup rename failed: {0}" -f $_.Exception.Message) }
                return $false
            }
        }

        try {
            $relative = ($SourceBackup -replace '^[A-Za-z]:\\ib\\', '')
            $stableRoot = Join-Path $srcRoot "Aetheris_Mobile_Payloads"
            $stable = Join-Path $stableRoot $relative
            New-Item -ItemType Directory -Force -Path (Split-Path -Parent $stable) | Out-Null
            if (Test-Path -LiteralPath $stable) {
                $stable = $stable + "_" + [guid]::NewGuid().ToString("N").Substring(0,8)
            }
            Move-Item -LiteralPath $SourceBackup -Destination $stable -Force -ErrorAction Stop
            if (Test-Path -LiteralPath $DestBackup) {
                try { cmd.exe /c "rmdir `"$DestBackup`"" | Out-Null } catch {}
                Remove-Item -LiteralPath $DestBackup -Recurse -Force -ErrorAction SilentlyContinue
            }
            $linkOut = cmd.exe /c "mklink /J `"$DestBackup`" `"$stable`"" 2>&1 | Out-String
            if (Test-IosBackupComplete -Path $DestBackup) {
                $pointer = Join-Path $parent "EXTERNAL_IOS_PAYLOAD.json"
                (@{
                    case_path = $DestBackup
                    payload_path = $stable
                    type = "ios_backup"
                    complete = $true
                } | ConvertTo-Json -Depth 4) | Set-Content -LiteralPath $pointer -Encoding UTF8
                if ($LogPath) { Write-AcquireLog $LogPath ("Relocated temporary iOS backup out of X:\ib and linked case path: {0} -> {1}" -f $DestBackup, $stable) }
                return $true
            }
            if ($LogPath) { Write-AcquireLog $LogPath ("Stable iOS payload junction failed: {0}" -f $linkOut.Trim()) }
            return $false
        } catch {
            if ($LogPath) { Write-AcquireLog $LogPath ("Failed to relocate staged iOS payload: {0}" -f $_.Exception.Message) }
            return $false
        }
    }

    if (Test-Path -LiteralPath $DestBackup) {
        if (Test-IosBackupComplete -Path $DestBackup) { return $true }
        try { cmd.exe /c "rmdir `"$DestBackup`"" | Out-Null } catch { }
        Remove-Item -LiteralPath $DestBackup -Recurse -Force -ErrorAction SilentlyContinue
    }
    $linkOut = cmd.exe /c "mklink /J `"$DestBackup`" `"$SourceBackup`"" 2>&1 | Out-String
    if (Test-IosBackupComplete -Path $DestBackup) {
        if ($LogPath) { Write-AcquireLog $LogPath ("Linked existing iOS image: {0} -> {1}" -f $DestBackup, $SourceBackup) }
        return $true
    }
    if ($LogPath) { Write-AcquireLog $LogPath ("Junction failed: {0}" -f $linkOut.Trim()) }
    return $false
}

function Get-VolumeFreeBytes {
    param([string]$Path)
    if (-not $Path) { return [int64]0 }
    try {
        $root = [System.IO.Path]::GetPathRoot($Path)
        if (-not $root -or $root.Length -lt 1) { return [int64]0 }
        $letter = $root.Substring(0, 1)
        $drive = Get-PSDrive -Name $letter -PSProvider FileSystem -ErrorAction Stop
        return [int64]$drive.Free
    } catch {
        return [int64]0
    }
}

function Test-VolumeRoom {
    param([string]$Path, [int64]$MinBytes = 2147483648)
    return (Get-VolumeFreeBytes -Path $Path) -ge $MinBytes
}

function Get-AdbStageRoot {
    # repo\ap is the stable staging folder. A full evidence drive must not be
    # where adb writes the phone, so use the roomiest local volume instead.
    $repoStage = Join-Path (Get-RepoRoot) "ap"
    $repoFree = Get-VolumeFreeBytes -Path $repoStage
    if ($repoFree -ge 8GB) { return $repoStage }
    $bestLetter = $null
    $bestFree = $repoFree
    foreach ($letter in @("F", "D", "C", "E")) {
        if (-not (Test-Path -LiteralPath ($letter + ":\"))) { continue }
        $free = Get-VolumeFreeBytes -Path ($letter + ":\")
        if ($free -gt $bestFree) {
            $bestFree = $free
            $bestLetter = $letter
        }
    }
    if ($bestLetter -and $bestFree -ge 2GB) {
        return ($bestLetter + ":\aetheris-adb-stage")
    }
    return $repoStage
}

function Write-AcquireLog {
    param([string]$LogPath, [string]$Message)
    if (-not $LogPath) { return }
    $line = "[{0}] {1}" -f (Get-Date -Format "yyyy-MM-dd HH:mm:ss"), $Message
    $payload = [System.Text.Encoding]::UTF8.GetBytes($line + "`r`n")
    $safe = ($LogPath.ToLowerInvariant() -replace '[^a-z0-9]', '_')
    if ($safe.Length -gt 80) { $safe = $safe.Substring($safe.Length - 80) }
    $mutex = $null
    $held = $false
    try {
        $mutex = New-Object System.Threading.Mutex($false, ("Local\AetherisAcquireLog_" + $safe))
        $held = $mutex.WaitOne(2000)
    } catch {
        $held = $false
    }
    try {
        for ($tryN = 0; $tryN -lt 6; $tryN++) {
            $stream = $null
            try {
                $dir = Split-Path -Parent $LogPath
                if ($dir -and -not (Test-Path -LiteralPath $dir)) {
                    New-Item -ItemType Directory -Force -Path $dir -ErrorAction SilentlyContinue | Out-Null
                }
                # Share read and write so a log viewer cannot lock the collection out.
                $stream = [System.IO.File]::Open(
                    $LogPath,
                    [System.IO.FileMode]::Append,
                    [System.IO.FileAccess]::Write,
                    [System.IO.FileShare]::ReadWrite)
                $stream.Write($payload, 0, $payload.Length)
                $stream.Flush()
                return
            } catch {
                Start-Sleep -Milliseconds (50 * ($tryN + 1))
            } finally {
                if ($stream) { try { $stream.Dispose() } catch {} }
            }
        }
    } finally {
        if ($held -and $mutex) { try { [void]$mutex.ReleaseMutex() } catch {} }
        if ($mutex) { try { $mutex.Dispose() } catch {} }
    }
}

function Get-ShellPortableDeviceItem {
    param([string]$DeviceName, [string]$InstanceId = "")
    $shell = New-Object -ComObject Shell.Application
    $computer = $shell.NameSpace(0x11)
    if (-not $computer) { return $null }
    $items = @()
    try { $items = @($computer.Items()) } catch { return $null }
    $portable = @($items | Where-Object {
        $p = [string]$_.Path
        -not $p -or ($p -notmatch '^[A-Za-z]:\\')
    })
    if ($DeviceName) {
        $exact = $portable | Where-Object { [string]$_.Name -eq $DeviceName } | Select-Object -First 1
        if ($exact) { return $exact }
        $partial = $portable | Where-Object { [string]$_.Name -match [regex]::Escape($DeviceName) } | Select-Object -First 1
        if ($partial) { return $partial }
    }
    $vid = $null; $prodId = $null; $serial = $null
    if ($InstanceId -match 'VID_([0-9A-Fa-f]{4})') { $vid = $Matches[1] }
    if ($InstanceId -match 'PID_([0-9A-Fa-f]{4})') { $prodId = $Matches[1] }
    if ($InstanceId -match 'PID_[0-9A-Fa-f]{4}[^#\\]*[#\\]([^#\\&]+)') { $serial = $Matches[1] }
    if ($vid -and $prodId) {
        foreach ($item in $portable) {
            $p = [string]$item.Path
            if ($p -match "(?i)vid[_]?$vid" -and $p -match "(?i)pid[_]?$prodId") { return $item }
        }
    }
    if ($serial) {
        $hit = $portable | Where-Object { ([string]$_.Path) -match [regex]::Escape($serial) } | Select-Object -First 1
        if ($hit) { return $hit }
    }
    return ($portable | Where-Object {
        $_.Name -match '(?i)iPhone|iPad|Android|Phone|Samsung|Galaxy|Xiaomi|Huawei|OnePlus|Pixel|Oppo|Vivo|Redmi'
    } | Select-Object -First 1)
}

function Get-Win32LongPath {
    param([string]$Path)
    if (-not $Path) { return $Path }
    # PS 5.1 cannot parse '\\?\' in a single-quoted string (trailing \' closes the quote).
    $prefix = ([string][char]92) + [char]92 + '?' + [char]92
    if ($Path.StartsWith($prefix)) { return $Path }
    if ($Path -match '^[A-Za-z]:\\') { return $prefix + $Path }
    return $Path
}

function Get-DirFileStats {
    param([string]$Dir)
    if (-not $Dir -or -not (Test-Path -LiteralPath $Dir)) {
        return @{ files = 0; bytes = [int64]0 }
    }
    $n = 0
    $bytes = [int64]0
    $enumDir = Get-Win32LongPath -Path $Dir
    $stack = New-Object System.Collections.Generic.Stack[string]
    $stack.Push($enumDir)
    while ($stack.Count -gt 0) {
        $cur = $stack.Pop()
        try {
            foreach ($sub in [System.IO.Directory]::EnumerateDirectories($cur)) {
                try {
                    $attr = [System.IO.File]::GetAttributes($sub)
                    if ($attr -band [System.IO.FileAttributes]::ReparsePoint) { continue }
                } catch {}
                $stack.Push($sub)
            }
        } catch {}
        try {
            foreach ($f in [System.IO.Directory]::EnumerateFiles($cur)) {
                $n++
                try { $bytes += ([System.IO.FileInfo]$f).Length } catch {}
            }
        } catch {}
    }
    return @{ files = $n; bytes = [int64]$bytes }
}

function Copy-ShellItemToFolder {
    param(
        $ShellItem,
        [string]$DestDir,
        [int]$TimeoutSec = 8,
        [int]$CopyFlags = 528
    )
    if (-not $ShellItem) { return $false }
    New-Item -ItemType Directory -Force -Path $DestDir | Out-Null
    $shell = New-Object -ComObject Shell.Application
    $destNs = $shell.NameSpace($DestDir)
    if (-not $destNs) { return $false }
    $name = [string]$ShellItem.Name
    if (-not $name) { return $false }
    $target = Join-Path $DestDir $name
    if (Test-Path -LiteralPath $target) { return $true }
    # 16=Yes to all, 512=No confirm mkdir. Do NOT use FOF_SILENT (4): Windows
    # MTP CopyHere with silent flags often creates nothing.
    try {
        $destNs.CopyHere($ShellItem, $CopyFlags)
    }
    catch {
        return $false
    }
    $sw = [System.Diagnostics.Stopwatch]::StartNew()
    while ($sw.Elapsed.TotalSeconds -lt $TimeoutSec) {
        if (Test-Path -LiteralPath $target) { return $true }
        Start-Sleep -Milliseconds 200
    }
    return (Test-Path -LiteralPath $target)
}

function Copy-MtpDeviceLogical {
    param(
        [string]$DeviceName,
        [string]$InstanceId,
        [string]$DestDir,
        [string]$LogPath,
        [string]$OsHint = "other",
        [int]$MaxDepth = 4,
        [int]$MaxFiles = 200,
        [int]$MaxSeconds = 75,
        [string]$ProgressFile = "",
        [int]$AdbFilesCopied = 0,
        [int64]$AdbBytesCopied = 0
    )
    New-Item -ItemType Directory -Force -Path $DestDir | Out-Null
    if ([System.Threading.Thread]::CurrentThread.GetApartmentState() -ne 'STA' -and -not $env:AETHERIS_MTP_STA) {
        $copyScript = Join-Path $PSScriptRoot "mtp_logical_copy.ps1"
        if (-not (Test-Path -LiteralPath $copyScript)) {
            $copyScript = Join-Path (Split-Path -Parent $PSCommandPath) "mtp_logical_copy.ps1"
        }
        if (Test-Path -LiteralPath $copyScript) {
            $env:AETHERIS_MTP_STA = "1"
            $raw = & powershell.exe -STA -NoProfile -ExecutionPolicy Bypass -File $copyScript `
                -InstanceId $InstanceId -DeviceName $DeviceName -DestDir $DestDir -LogPath $LogPath -OsHint $OsHint 2>&1 | Out-String
            $line = ($raw -split '[\r\n]+' | Where-Object { $_.Trim().StartsWith('{') } | Select-Object -Last 1)
            if ($line) { try { return ($line | ConvertFrom-Json) } catch {} }
            return @{ ok = $false; files_copied = 0; error = $(if ($raw) { $raw.Trim() } else { "mtp_sta_relaunch_failed" }) }
        }
    }
    $rootItem = Get-ShellPortableDeviceItem -DeviceName $DeviceName -InstanceId $InstanceId
    if (-not $rootItem) {
        $listed = @()
        try {
            $shell = New-Object -ComObject Shell.Application
            $computer = $shell.NameSpace(0x11)
            if ($computer) {
                foreach ($it in @($computer.Items())) {
                    if ([string]$it.Path -notmatch '^[A-Za-z]:\\') { $listed += [string]$it.Name }
                }
            }
        } catch {}
        Write-AcquireLog $LogPath ("MTP device not found under This PC (unlock phone, File transfer). Visible: " + ($listed -join ", "))
        return @{ ok = $false; files_copied = 0; error = "mtp_device_not_found" }
    }
    Write-AcquireLog $LogPath ("MTP device found: {0}" -f $rootItem.Name)

    $os = ([string]$OsHint).ToLowerInvariant()
    if ($os -eq "ios") {
        # iPhone MTP often stalls on opaque Internal Storage nodes; keep this bounded.
        $MaxDepth = [Math]::Min($MaxDepth, 3)
        $MaxFiles = [Math]::Min($MaxFiles, 80)
        $MaxSeconds = [Math]::Min($MaxSeconds, 60)
    }
    elseif ($os -eq "android") {
        # Raise floors only when the caller left the defaults (bounded tests can pass lower).
        if ($MaxDepth -eq 4) { $MaxDepth = 20 }
        if ($MaxFiles -eq 200) { $MaxFiles = 500000 }
        if ($MaxSeconds -eq 75) { $MaxSeconds = 14400 }
    }

    $state = @{ copied = 0 }
    $errors = New-Object System.Collections.Generic.List[string]
    $deadline = [DateTime]::UtcNow.AddSeconds($MaxSeconds)

    function Write-MtpProgress {
        param([string]$Detail)
        if (-not $ProgressFile) { return }
        $stats = Get-DirFileStats -Dir $DestDir
        $prevFiles = 0
        $prevBytes = [int64]0
        if (Test-Path -LiteralPath $ProgressFile) {
            try {
                $prev = Get-Content -LiteralPath $ProgressFile -Raw -ErrorAction SilentlyContinue | ConvertFrom-Json
                $prevFiles = [int]$prev.files_seen
                $prevBytes = [int64]$prev.bytes_done
            } catch {}
        }
        $files = [Math]::Max($AdbFilesCopied + [int]$stats.files, $prevFiles)
        $bytes = [Math]::Max($AdbBytesCopied + [int64]$stats.bytes, $prevBytes)
        $obj = @{
            stage      = "acquire"
            item       = "mtp_shared"
            bytes_done = $bytes
            files_seen = $files
            detail     = $(if ($Detail) { $Detail } else { "Copying shared storage from the phone" })
            category   = "Collecting"
        }
        try { ($obj | ConvertTo-Json -Compress -Depth 6) | Set-Content -LiteralPath $ProgressFile -Encoding UTF8 } catch {}
    }

    function Test-MtpBudgetOk {
        if ($ProgressFile -and (Test-Path -LiteralPath ($ProgressFile + ".cancel"))) { return $false }
        return ([DateTime]::UtcNow -lt $deadline) -and ($state.copied -lt $MaxFiles)
    }

    function Wait-MtpCopyProgress {
        param([int]$StableSeconds = 12)
        $last = -1
        $stableFor = 0
        while (Test-MtpBudgetOk) {
            $stats = Get-DirFileStats -Dir $DestDir
            $state.copied = [int]$stats.files
            Write-MtpProgress ("Copied {0} file(s) ({1} bytes)" -f $stats.files, $stats.bytes)
            if ($stats.files -gt 0 -and $stats.files -eq $last) {
                $stableFor += 2
                if ($stableFor -ge $StableSeconds) { return }
            } else {
                $stableFor = 0
            }
            $last = [int]$stats.files
            Start-Sleep -Seconds 2
        }
    }

    function Walk-ShellFolder {
        param($FolderItem, [string]$FsPath, [int]$Depth)
        if ($Depth -gt $MaxDepth -or -not (Test-MtpBudgetOk)) { return }
        New-Item -ItemType Directory -Force -Path $FsPath | Out-Null
        $folder = $null
        try { $folder = $FolderItem.GetFolder } catch { return }
        if (-not $folder) { return }
        $children = @()
        try { $children = @($folder.Items()) } catch { return }
        foreach ($child in $children) {
            if (-not (Test-MtpBudgetOk)) { break }
            $childName = [string]$child.Name
            if (-not $childName) { continue }
            $isFolder = $false
            try { $isFolder = [bool]$child.IsFolder } catch { $isFolder = $false }
            if ($isFolder) {
                Walk-ShellFolder -FolderItem $child -FsPath (Join-Path $FsPath $childName) -Depth ($Depth + 1)
                continue
            }
            $okCopy = Copy-ShellItemToFolder -ShellItem $child -DestDir $FsPath -TimeoutSec 20 -CopyFlags 528
            if ($okCopy) {
                $state.copied++
                if (($state.copied % 10) -eq 0) {
                    Write-AcquireLog $LogPath ("MTP copied {0} file(s)..." -f $state.copied)
                    Write-MtpProgress ("Copied {0} file(s)" -f $state.copied)
                }
            }
            else {
                $errors.Add("copy_failed:$childName") | Out-Null
            }
        }
    }

    $rootFolder = $null
    try { $rootFolder = $rootItem.GetFolder } catch { $rootFolder = $null }
    if ($rootFolder) {
        $tops = @($rootFolder.Items())
        # Prefer media-like folders first (especially for iOS MTP).
        $ranked = @($tops | Sort-Object {
            $n = [string]$_.Name
            if ($n -match '(?i)Trash|\.trashed|Recycle|DCIM|Photo|Picture|Camera|Download|WhatsApp|Telegram|Document|File') { "0$n" }
            elseif ($n -match '(?i)Internal|Storage|Phone|Card|SD') { "1$n" }
            else { "2$n" }
        })
        $flagSets = @(528, 16, 0)
        $script:MtpWinningFlags = $null
        $copyOnce = Join-Path $PSScriptRoot "mtp_copyhere_once.ps1"
        if (-not (Test-Path -LiteralPath $copyOnce) -and $PSCommandPath) {
            $copyOnce = Join-Path (Split-Path -Parent $PSCommandPath) "mtp_copyhere_once.ps1"
        }

        function Invoke-BoundedMtpCopyHere {
            param([string]$RelativePath, [string]$Label, [int]$IdleSec = 25)
            if (-not $RelativePath -or -not (Test-MtpBudgetOk)) { return $false }
            if ($IdleSec -lt 25) { $IdleSec = 25 }
            Write-AcquireLog $LogPath ("MTP copy '{0}'" -f $RelativePath)
            Write-MtpProgress ("Copying {0}" -f $Label)
            $before = [int](Get-DirFileStats -Dir $DestDir).files
            $copiedThis = $false
            $tryFlags = $(if ($null -ne $script:MtpWinningFlags) { @($script:MtpWinningFlags) } else { $flagSets })
            foreach ($flags in $tryFlags) {
                if (-not (Test-Path -LiteralPath $copyOnce)) { break }
                $arg = '-STA -NoProfile -ExecutionPolicy Bypass -File "{0}" -DestDir "{1}" -DeviceName "{2}" -InstanceId "{3}" -RelativePath "{4}" -Flags {5}' -f $copyOnce, $DestDir, $DeviceName, $InstanceId, $RelativePath, $flags
                $p = $null
                try {
                    $p = Start-Process -FilePath "powershell.exe" -ArgumentList $arg -PassThru -WindowStyle Hidden
                } catch { $p = $null }
                if (-not $p) { continue }
                $started = [DateTime]::UtcNow
                $gotFiles = $false
                $lastSeen = $before
                $lastGrowthAt = [DateTime]::UtcNow
                while ($true) {
                    $statsNow = Get-DirFileStats -Dir $DestDir
                    $nNow = [int]$statsNow.files
                    if ($nNow -gt $before) {
                        $gotFiles = $true
                        $state.copied = $nNow
                        Write-MtpProgress ("Copied {0} file(s) from {1}" -f $nNow, $Label)
                    }
                    if ($nNow -gt $lastSeen) {
                        $lastSeen = $nNow
                        $lastGrowthAt = [DateTime]::UtcNow
                    }
                    $exited = $false
                    try { $exited = $p.HasExited } catch { $exited = $true }
                    $elapsed = ([DateTime]::UtcNow - $started).TotalSeconds
                    $stalledFor = ([DateTime]::UtcNow - $lastGrowthAt).TotalSeconds
                    if ($gotFiles) {
                        # Explorer CopyHere often never returns on large Android/media trees.
                        if ($exited -or -not (Test-MtpBudgetOk) -or $stalledFor -ge 90) {
                            if (-not $exited) {
                                if ($stalledFor -ge 90) {
                                    Write-AcquireLog $LogPath ("MTP CopyHere of '{0}' stalled at {1} file(s) for {2}s - moving on." -f $RelativePath, $nNow, [int]$stalledFor)
                                }
                                try { & taskkill.exe /PID $p.Id /T /F 2>$null | Out-Null } catch {}
                            }
                            break
                        }
                    }
                    else {
                        if ($exited) {
                            $until = [DateTime]::UtcNow.AddSeconds(20)
                            while ([DateTime]::UtcNow -lt $until -and (Test-MtpBudgetOk)) {
                                $late = [int](Get-DirFileStats -Dir $DestDir).files
                                if ($late -gt $before) { $gotFiles = $true; break }
                                Start-Sleep -Milliseconds 500
                            }
                            break
                        }
                        if ($elapsed -ge $IdleSec) {
                            Write-AcquireLog $LogPath ("MTP CopyHere of '{0}' produced no files in {1}s - skipping that copy." -f $RelativePath, $IdleSec)
                            try { & taskkill.exe /PID $p.Id /T /F 2>$null | Out-Null } catch {}
                            break
                        }
                    }
                    Start-Sleep -Milliseconds 500
                }
                if ($gotFiles) {
                    $copiedThis = $true
                    $script:MtpWinningFlags = [int]$flags
                    break
                }
            }
            if ($copiedThis) {
                Wait-MtpCopyProgress -StableSeconds 8
                $state.copied = [int](Get-DirFileStats -Dir $DestDir).files
                Write-AcquireLog $LogPath ("MTP copy of '{0}' now at {1} file(s)" -f $RelativePath, $state.copied)
            }
            return $copiedThis
        }

        foreach ($top in $ranked) {
            if (-not (Test-MtpBudgetOk)) { break }
            $topName = [string]$top.Name
            $isFolder = $false
            try { $isFolder = [bool]$top.IsFolder } catch { $isFolder = $false }
            if ($os -eq "ios" -and $topName -match '(?i)^(Internal Storage|Internal|Storage|iPhone|Apple iPhone)$') {
                Write-AcquireLog $LogPath ("Skipping opaque iOS MTP node '{0}' (CopyHere hangs with 0 files)." -f $topName)
                continue
            }
            if (-not $isFolder) {
                if (Copy-ShellItemToFolder -ShellItem $top -DestDir $DestDir -TimeoutSec 8 -CopyFlags 528) {
                    $state.copied++
                }
                continue
            }
            if ($os -eq "ios") {
                Write-AcquireLog $LogPath ("iOS MTP walk '{0}' (no bulk CopyHere)." -f $topName)
                Write-MtpProgress ("Walking {0}" -f $topName)
                Walk-ShellFolder -FolderItem $top -FsPath (Join-Path $DestDir $topName) -Depth 0
                continue
            }
            $isStorageRoot = ($topName -match '(?i)^(Phone|Internal Storage|Internal|Storage|Card|SD Card|SD)$')
            if ($isStorageRoot) {
                Write-AcquireLog $LogPath ("Android storage root '{0}' - copying child folders (not walking the whole tree)." -f $topName)
                $inner = $null
                try { $inner = $top.GetFolder } catch { $inner = $null }
                $kids = @()
                try { if ($inner) { $kids = @($inner.Items()) } } catch { $kids = @() }
                if (-not $kids.Count) {
                    [void](Invoke-BoundedMtpCopyHere -RelativePath $topName -Label $topName)
                    continue
                }
                $kidRanked = @($kids | Sort-Object {
                    $n = [string]$_.Name
                    if ($n -match '(?i)^(Android|WhatsApp|Telegram|DCIM|Pictures|Download|Documents|Movies|Music)$') { "0$n" }
                    else { "1$n" }
                })
                foreach ($kid in $kidRanked) {
                    if (-not (Test-MtpBudgetOk)) { break }
                    $kidName = [string]$kid.Name
                    if (-not $kidName) { continue }
                    if ($kidName -match '(?i)whatsapp' -and $env:AETHERIS_SKIP_MTP_WHATSAPP -eq "1") {
                        Write-AcquireLog $LogPath ("Skipping MTP '{0}' - ADB already copied WhatsApp." -f $kidName)
                        continue
                    }
                    $rel = $topName + '\' + $kidName
                    $idle = 25
                    if ($kidName -match '(?i)Android|WhatsApp|Telegram|DCIM|Pictures') { $idle = 90 }
                    $kidIsFolder = $false
                    try { $kidIsFolder = [bool]$kid.IsFolder } catch { $kidIsFolder = $false }
                    if ($kidIsFolder -and $kidName -match '(?i)^Android$') {
                        if ($env:AETHERIS_SKIP_MTP_WHATSAPP -eq "1") {
                            Write-AcquireLog $LogPath "Skipping MTP Android/media and Android/data - ADB already copied those packages."
                            continue
                        }
                        Write-AcquireLog $LogPath "Android folder - copying media/data package children (WhatsApp lives here)."
                        $andInner = $null
                        try { $andInner = $kid.GetFolder } catch { $andInner = $null }
                        $andKids = @()
                        try { if ($andInner) { $andKids = @($andInner.Items()) } } catch { $andKids = @() }
                        if (-not $andKids.Count) {
                            [void](Invoke-BoundedMtpCopyHere -RelativePath $rel -Label $kidName -IdleSec $idle)
                            continue
                        }
                        foreach ($sub in $andKids) {
                            if (-not (Test-MtpBudgetOk)) { break }
                            $subName = [string]$sub.Name
                            if (-not $subName) { continue }
                            $subRel = $rel + '\' + $subName
                            $subFolder = $null
                            try { if ([bool]$sub.IsFolder) { $subFolder = $sub.GetFolder } } catch { $subFolder = $null }
                            $pkgs = @()
                            try { if ($subFolder) { $pkgs = @($subFolder.Items()) } } catch { $pkgs = @() }
                            if ($subName -match '(?i)media|data' -and $pkgs.Count) {
                                $pkgRanked = @($pkgs | Sort-Object {
                                    $pn = [string]$_.Name
                                    if ($pn -match '(?i)whatsapp|telegram|instagram|facebook|snapchat|signal') { "0$pn" }
                                    else { "1$pn" }
                                })
                                foreach ($pkg in $pkgRanked) {
                                    if (-not (Test-MtpBudgetOk)) { break }
                                    $pkgName = [string]$pkg.Name
                                    if (-not $pkgName) { continue }
                                    if ($pkgName -match '(?i)whatsapp' -and $env:AETHERIS_SKIP_MTP_WHATSAPP -eq "1") {
                                        Write-AcquireLog $LogPath ("Skipping MTP '{0}' - ADB already copied WhatsApp." -f $pkgName)
                                        continue
                                    }
                                    $pkgIdle = 90
                                    if ($pkgName -match '(?i)whatsapp') { $pkgIdle = 180 }
                                    [void](Invoke-BoundedMtpCopyHere -RelativePath ($subRel + '\' + $pkgName) -Label $pkgName -IdleSec $pkgIdle)
                                }
                            } else {
                                [void](Invoke-BoundedMtpCopyHere -RelativePath $subRel -Label $subName -IdleSec $idle)
                            }
                        }
                        continue
                    }
                    [void](Invoke-BoundedMtpCopyHere -RelativePath $rel -Label $kidName -IdleSec $idle)
                }
                continue
            }
            [void](Invoke-BoundedMtpCopyHere -RelativePath $topName -Label $topName)
        }
    }

    if (-not (Test-MtpBudgetOk)) {
        Write-AcquireLog $LogPath ("MTP copy stopped at budget (files={0}, maxSeconds={1})." -f $state.copied, $MaxSeconds)
    }
    # CopyHere is asynchronous; allow late arrivals before counting.
    Start-Sleep -Seconds 4
    $diskCount = [int](Get-DirFileStats -Dir $DestDir).files
    if ($diskCount -gt $state.copied) { $state.copied = $diskCount }
    Write-AcquireLog $LogPath ("MTP logical copy finished: {0} file(s)" -f $state.copied)
    Write-MtpProgress ("MTP logical copy finished: {0} file(s)" -f $state.copied)
    return @{
        ok           = ($state.copied -gt 0)
        files_copied = [int]$state.copied
        error        = if ($state.copied -gt 0) { $null } else { "mtp_no_files_copied" }
        errors       = @($errors | Select-Object -First 20)
    }
}

function ConvertFrom-AcquireJsonText {
    param([string]$Raw)
    if ([string]::IsNullOrWhiteSpace($Raw)) { return $null }
    $trim = $Raw.Trim()
    try { return ($trim | ConvertFrom-Json) } catch {}
    $start = $trim.IndexOf('{')
    $end = $trim.LastIndexOf('}')
    if ($start -ge 0 -and $end -gt $start) {
        $slice = $trim.Substring($start, $end - $start + 1)
        try { return ($slice | ConvertFrom-Json) } catch {}
    }
    $line = ($trim -split "`r?`n" | Where-Object { $_.Trim().StartsWith("{") } | Select-Object -Last 1)
    if ($line) {
        try { return ($line | ConvertFrom-Json) } catch {}
    }
    return $null
}

function Convert-PsObjectToHashtable {
    param($Obj)
    if ($null -eq $Obj) { return @{} }
    if ($Obj -is [hashtable]) { return $Obj }
    $out = @{}
    foreach ($p in $Obj.PSObject.Properties) {
        $val = $p.Value
        if ($val -is [System.Management.Automation.PSCustomObject]) {
            $out[$p.Name] = Convert-PsObjectToHashtable $val
        } elseif ($val -is [System.Collections.IEnumerable] -and -not ($val -is [string])) {
            $out[$p.Name] = @($val)
        } else {
            $out[$p.Name] = $val
        }
    }
    return $out
}

function Get-ExportCatalogFromDisk {
    param([string]$Exports)
    $out = @{ ok = $false; packages = @{}; package_sha256 = @{}; warnings = @() }
    if (-not $Exports -or -not (Test-Path -LiteralPath $Exports)) { return $out }
    # V22: sidecar JSON lives in 07_Logs/<run>, not beside the packages.
    $runName = Split-Path -Leaf $Exports
    $caseRoot = Split-Path -Parent (Split-Path -Parent $Exports)
    $cat = Join-Path (Join-Path (Join-Path $caseRoot "07_Logs") $runName) "export_catalog.json"
    if (-not (Test-Path -LiteralPath $cat)) { $cat = Join-Path $Exports "export_catalog.json" }
    if (Test-Path -LiteralPath $cat) {
        try {
            $obj = Get-Content -LiteralPath $cat -Raw -Encoding UTF8 | ConvertFrom-Json
            if ($obj.packages) {
                $pkgs = @{}
                foreach ($p in $obj.packages.PSObject.Properties) {
                    if ($p.Value) { $pkgs[$p.Name] = [string]$p.Value }
                }
                $sha = @{}
                if ($obj.package_sha256) {
                    foreach ($p in $obj.package_sha256.PSObject.Properties) {
                        if ($p.Value) { $sha[$p.Name] = [string]$p.Value }
                    }
                }
                $warn = @()
                if ($obj.warnings) { $warn = @($obj.warnings | ForEach-Object { [string]$_ }) }
                if ($pkgs.Count -gt 0) {
                    return @{
                        ok             = $true
                        run_name       = [string]$obj.run_name
                        export_dir     = [string]$obj.export_dir
                        packages       = $pkgs
                        package_sha256 = $sha
                        format_note    = [string]$obj.format_note
                        warnings       = $warn
                    }
                }
            }
        } catch {}
    }
    foreach ($ext in @("zip", "ufdx", "ufd", "pas")) {
        $hit = Get-ChildItem -LiteralPath $Exports -Filter ("*." + $ext) -File -ErrorAction SilentlyContinue |
            Select-Object -First 1
        if ($hit) { $out.packages[$ext] = $hit.FullName }
    }
    if ($out.packages.Count -gt 0) { $out.ok = $true }
    return $out
}

function Convert-AcquireResultToJson {
    param([hashtable]$Obj)
    $json = $Obj | ConvertTo-Json -Compress -Depth 12
    if (-not $json) { return "{}" }
    $json = $json -replace '"errors":\{\}', '"errors":[]'
    $json = $json -replace '"extraction_data":\{\}', '"extraction_data":[]'
    $json = $json -replace '"limitations":\{\}', '"limitations":[]'
    $json = $json -replace '"error":null', '"error":""'
    return $json
}

function Invoke-HostExportPackages {
    param(
        [string]$Original,
        [string]$Exports,
        [string]$Logs = "",
        [string]$Hashes = "",
        [string]$CaseId = "",
        [string]$EvidenceId = "",
        [string]$Method = "logical",
        [string]$ProgressFile = "",
        [string]$LogPath = ""
    )
    $out = @{
        ok          = $false
        inventory   = @{}
        export      = @{ packages = @{} }
        error       = ""
    }
    if (-not $Original -or -not (Test-Path -LiteralPath $Original)) {
        $out.error = "original_missing"
        return $out
    }
    $py = Find-KitPython
    $backend = Join-Path (Get-RepoRoot) "backend"
    if (-not $py -or -not (Test-Path -LiteralPath $backend)) {
        Write-AcquireLog $LogPath "Examiner kit python missing - skipping .zip/.ufd/.pas export."
        $out.error = "examiner_kit_python_missing"
        return $out
    }
    New-Item -ItemType Directory -Force -Path $Exports | Out-Null
    if ($Hashes) { New-Item -ItemType Directory -Force -Path $Hashes | Out-Null }
    $prevBytes = [int64]0
    $prevFiles = 0
    if ($ProgressFile -and (Test-Path -LiteralPath $ProgressFile)) {
        try {
            $prevProg = Get-Content -LiteralPath $ProgressFile -Raw -Encoding UTF8 | ConvertFrom-Json
            $prevBytes = [int64]($prevProg.bytes_done)
            $prevFiles = [int]($prevProg.files_seen)
        } catch {}
    }
    if ($ProgressFile) {
        try {
            (@{
                stage         = "seal"
                item          = "export_packages"
                detail        = "Writing portable metadata packages; sealed image stays in Original"
                category      = "Sealing"
                bytes_done    = $prevBytes
                files_seen    = $prevFiles
                progress_pct  = 90
                phase         = "export_zip"
                phase_progress_pct = 0
                output_path   = $Exports
            } | ConvertTo-Json -Compress) | Set-Content -LiteralPath $ProgressFile -Encoding UTF8
        } catch {}
    }
    Write-AcquireLog $LogPath ("Writing full evidence ZIP + .ufd/.pas/.ufdx into {0} (extract/RAG reads the zip only)" -f $Exports)
    $errFile = Join-Path $env:TEMP ("aetheris_export_" + [guid]::NewGuid().ToString("N") + ".err")
    $outFile = Join-Path $env:TEMP ("aetheris_export_" + [guid]::NewGuid().ToString("N") + ".out")
    $prevPy = $env:PYTHONPATH
    $env:PYTHONPATH = Get-KitPythonPathEnv
    $args = @(
        "-m", "app.services.mobile_acquire.export_cli",
        "--original", $Original,
        "--exports", $Exports,
        "--method", $Method
    )
    if ($CaseId) { $args += @("--case-id", $CaseId) }
    if ($EvidenceId) { $args += @("--evidence-id", $EvidenceId) }
    if ($Logs) { $args += @("--logs", $Logs) }
    if ($Hashes) { $args += @("--hashes", $Hashes) }
    if ($ProgressFile) { $args += @("--progress-file", $ProgressFile) }
    $args += "--full"
    $proc = $null
    try {
        $proc = Start-Process -FilePath $py -ArgumentList $args -WorkingDirectory $backend `
            -PassThru -NoNewWindow -RedirectStandardOutput $outFile -RedirectStandardError $errFile
        $timeoutMinutes = 180
        try { if ($env:AETHERIS_EXPORT_TIMEOUT_MINUTES) { $timeoutMinutes = [int]$env:AETHERIS_EXPORT_TIMEOUT_MINUTES } } catch {}
        $deadline = (Get-Date).AddMinutes($timeoutMinutes)
        while ($proc -and -not $proc.HasExited -and (Get-Date) -lt $deadline) {
            Start-Sleep -Seconds 2
        }
        if ($proc -and -not $proc.HasExited) {
            Write-AcquireLog $LogPath ("Evidence ZIP export exceeded {0} minutes - stopping the package writer." -f $timeoutMinutes)
            & taskkill.exe /PID $proc.Id /T /F 2>$null | Out-Null
            $out.error = "payload_export_timeout"
        } else {
            try { $proc.WaitForExit() } catch {}
        }
    } catch {
        $out.error = $_.Exception.Message
    }
    $env:PYTHONPATH = $prevPy
    $raw = ""
    if (Test-Path -LiteralPath $outFile) {
        $raw = Get-Content -LiteralPath $outFile -Raw -ErrorAction SilentlyContinue
    }
    $errTail = ""
    if (Test-Path -LiteralPath $errFile) {
        $errTail = Get-Content -LiteralPath $errFile -Raw -ErrorAction SilentlyContinue
    }
    Remove-Item -LiteralPath $outFile, $errFile -Force -ErrorAction SilentlyContinue
    $parsed = ConvertFrom-AcquireJsonText $raw
    if ($parsed -and $parsed.ok) {
        $out.ok = $true
        if ($parsed.inventory) { $out.inventory = Convert-PsObjectToHashtable $parsed.inventory }
        if ($parsed.export) { $out.export = Convert-PsObjectToHashtable $parsed.export }
        $out.error = ""
    } elseif ($parsed -and -not $parsed.ok) {
        $out.error = [string]($parsed.error)
    } elseif ($proc -and $proc.ExitCode -ne 0) {
        $out.error = $(if ($errTail) { ($errTail -replace '\s+', ' ').Trim() } else { "export_cli_failed" })
    }
    $disk = Get-ExportCatalogFromDisk $Exports
    if ($disk.ok -and $disk.packages -and $disk.packages.Count -gt 0) {
        $out.ok = $true
        if (-not $out.export) { $out.export = @{ packages = @{} } }
        if (-not $out.export.packages -or $out.export.packages.Count -eq 0) {
            $out.export = $disk
        }
        if ($out.error -eq "export_json_parse_failed" -or $out.error -eq "export_cli_failed") {
            $out.error = ""
        }
    }
    if ($out.ok) {
        Write-AcquireLog $LogPath "Portable packages and content inventory written."
    } elseif ($out.error) {
        Write-AcquireLog $LogPath ("Package export failed: {0}" -f $out.error)
    }
    return $out
}

function Wait-AdbDevice {
    param($Adb, [string]$LogPath, [int]$Seconds = 50)
    $lines = @()
    try { $lines = @(& $Adb devices 2>$null) } catch { $lines = @() }
    foreach ($line in $lines) {
        $t = ([string]$line).Trim()
        if ($t -match '\s+device$') {
            Write-AcquireLog $LogPath ("adb device already ready: {0}" -f $t)
            return "device"
        }
    }
    Write-AcquireLog $LogPath "Restarting adb so USB debugging is visible beside MTP/file-transfer..."
    try {
        Get-Process -Name adb -ErrorAction SilentlyContinue | Stop-Process -Force -ErrorAction SilentlyContinue
    } catch {}
    Start-Sleep -Milliseconds 800
    try { & $Adb kill-server 2>$null | Out-Null } catch {}
    Start-Sleep -Milliseconds 800
    try { & $Adb start-server 2>$null | Out-Null } catch {}
    $deadline = (Get-Date).AddSeconds($Seconds)
    $sawUnauthorized = $false
    while ((Get-Date) -lt $deadline) {
        $lines = @()
        try { $lines = @(& $Adb devices 2>$null) } catch { $lines = @() }
        foreach ($line in $lines) {
            $t = ([string]$line).Trim()
            if ($t -match '\s+unauthorized$') {
                $sawUnauthorized = $true
                Write-AcquireLog $LogPath "Phone is in adb unauthorized - unlock and tap Allow USB debugging."
            }
            elseif ($t -match '\s+device$') {
                Write-AcquireLog $LogPath ("adb device ready: {0}" -f $t)
                return "device"
            }
        }
        Start-Sleep -Seconds 2
    }
    if ($sawUnauthorized) { return "unauthorized" }
    return "none"
}

function Invoke-AdbExtractBackup {
    param([string]$AbPath, [string]$DestDir, [string]$LogPath)
    if (-not $AbPath -or -not (Test-Path -LiteralPath $AbPath)) { return 0 }
    if ((Get-Item -LiteralPath $AbPath).Length -lt 64) { return 0 }
    $py = Find-KitPython
    $backend = Join-Path (Get-RepoRoot) "backend"
    if (-not $py -or -not (Test-Path -LiteralPath $backend)) { return 0 }
    New-Item -ItemType Directory -Force -Path $DestDir | Out-Null
    $prev = $env:PYTHONPATH
    $env:PYTHONPATH = Get-KitPythonPathEnv
    try {
        $raw = & $py -m app.services.mobile_acquire.android_backup --ab $AbPath --out $DestDir 2>&1 | Out-String
        Write-AcquireLog $LogPath ("adb backup extract: {0}" -f ($raw -replace '\s+', ' ').Trim())
    } catch {
        Write-AcquireLog $LogPath ("adb backup extract failed: {0}" -f $_.Exception.Message)
    }
    $env:PYTHONPATH = $prev
    return @(Get-ChildItem -LiteralPath $DestDir -Recurse -File -ErrorAction SilentlyContinue).Count
}

function Invoke-AdbProviderDump {
    param($Adb, [string]$OutDir, [string]$LogPath)
    $prov = Join-Path $OutDir "providers"
    New-Item -ItemType Directory -Force -Path $prov | Out-Null
    $uris = @(
        @{ n = "sms"; u = "content://sms" },
        @{ n = "mms"; u = "content://mms" },
        @{ n = "call_log"; u = "content://call_log/calls" },
        @{ n = "contacts"; u = "content://com.android.contacts/data" },
        @{ n = "calendar"; u = "content://com.android.calendar/events" }
    )
    $got = 0
    foreach ($x in $uris) {
        $out = Join-Path $prov ($x.n + ".txt")
        $err = Join-Path $prov ($x.n + ".err.txt")
        try {
            $proc = Start-Process -FilePath $Adb -ArgumentList @("shell", "content", "query", "--uri", $x.u) `
                -PassThru -NoNewWindow -RedirectStandardOutput $out -RedirectStandardError $err
            if ($proc) {
                $done = $false
                try { $done = $proc.WaitForExit(45000) } catch { $done = $false }
                if (-not $done) { try { & taskkill.exe /PID $proc.Id /T /F 2>$null | Out-Null } catch {} }
            }
        } catch {}
        $len = 0
        if (Test-Path -LiteralPath $out) { $len = [int64](Get-Item -LiteralPath $out).Length }
        $body = ""
        if ($len -gt 0) { $body = Get-Content -LiteralPath $out -Raw -ErrorAction SilentlyContinue }
        if ($len -gt 40 -and $body -notmatch '(?i)Permission Denial|SecurityException|Could not find provider') {
            Write-AcquireLog $LogPath ("Provider {0}: {1} byte(s)" -f $x.n, $len)
            $got++
        }
    }
    return $got
}

function Invoke-AdbStreamTar {
    param(
        $Adb,
        [string]$RemoteDir,
        [string]$DestDir,
        [string]$LogPath,
        [string]$ProgressFile = "",
        [switch]$Su
    )
    $py = Find-KitPython
    if (-not $py) {
        Write-AcquireLog $LogPath "Kit Python not found - cannot stream adb tar (needed to avoid Windows MAX_PATH)."
        return 0
    }
    New-Item -ItemType Directory -Force -Path $DestDir | Out-Null
    $prev = $env:PYTHONPATH
    $env:PYTHONPATH = Get-KitPythonPathEnv
    $args = @("-m", "app.services.mobile_acquire.adb_tar_pull", "--adb", $Adb, "--remote", $RemoteDir, "--out", $DestDir)
    if ($ProgressFile) { $args += @("--progress", $ProgressFile) }
    if ($Su) { $args += "--su" }
    $raw = ""
    try {
        $raw = & $py @args 2>&1 | Out-String
    } catch {
        $raw = $_.Exception.Message
    }
    $env:PYTHONPATH = $prev
    $line = ($raw -split '[\r\n]+' | Where-Object { $_.Trim().StartsWith('{') } | Select-Object -Last 1)
    $n = 0
    $err = ""
    if ($line) {
        try {
            $obj = $line | ConvertFrom-Json
            $n = [int]$obj.files
            $err = [string]$obj.error
        } catch {}
    }
    if ($n -gt 0) {
        Write-AcquireLog $LogPath ("adb tar {0} copied {1} file(s)" -f $RemoteDir, $n)
    } else {
        Write-AcquireLog $LogPath ("adb tar {0} produced no files. {1}" -f $RemoteDir, (($err + " " + $raw) -replace '\s+', ' ').Trim())
    }
    return $n
}

function Write-AdbProgress {
    param([string]$ProgressFile, [string]$Remote, [int]$Files, [int64]$Bytes = 0)
    if (-not $ProgressFile) { return }
    $prevFiles = 0
    $prevBytes = [int64]0
    if ($null -eq $script:AdbPeakFiles) { $script:AdbPeakFiles = 0 }
    if ($null -eq $script:AdbPeakBytes) { $script:AdbPeakBytes = [int64]0 }
    if (Test-Path -LiteralPath $ProgressFile) {
        try {
            $prev = Get-Content -LiteralPath $ProgressFile -Raw -ErrorAction SilentlyContinue | ConvertFrom-Json
            $prevFiles = [int]$prev.files_seen
            $prevBytes = [int64]$prev.bytes_done
        } catch {}
    }
    $files = [Math]::Max([int]$Files, [Math]::Max($prevFiles, [int]$script:AdbPeakFiles))
    $bytes = [Math]::Max([int64]$Bytes, [Math]::Max($prevBytes, [int64]$script:AdbPeakBytes))
    $script:AdbPeakFiles = $files
    $script:AdbPeakBytes = $bytes
    try {
        (@{
            stage      = "acquire"
            item       = "adb_filesystem"
            bytes_done = $bytes
            files_seen = $files
            detail     = ("ADB pulling {0} - {1} file(s)" -f $Remote, $files)
            category   = "Collecting"
        } | ConvertTo-Json -Compress -Depth 6) | Set-Content -LiteralPath $ProgressFile -Encoding UTF8
    } catch {}
}

function Invoke-PyTreeJson {
    param([string[]]$ExtraArgs)
    $py = Find-KitPython
    if (-not $py) { return $null }
    $prev = $env:PYTHONPATH
    $env:PYTHONPATH = Get-KitPythonPathEnv
    $raw = ""
    try {
        $raw = & $py @(@("-m", "app.services.mobile_acquire.adb_tar_pull") + $ExtraArgs) 2>&1 | Out-String
    } catch {
        $raw = $_.Exception.Message
    }
    $env:PYTHONPATH = $prev
    $line = ($raw -split '[\r\n]+' | Where-Object { $_.Trim().StartsWith('{') } | Select-Object -Last 1)
    if (-not $line) { return $null }
    try { return ($line | ConvertFrom-Json) } catch { return $null }
}

function Test-AdbRemoteExists {
    param($Adb, [string]$RemoteDir)
    $outFile = Join-Path $env:TEMP ("aetheris_ls_" + [guid]::NewGuid().ToString("N") + ".txt")
    $errFile = $outFile + ".err"
    try {
        $p = Start-Process -FilePath $Adb -ArgumentList @("shell", "ls", $RemoteDir) -PassThru -NoNewWindow `
            -RedirectStandardOutput $outFile -RedirectStandardError $errFile
        if ($p) {
            $done = $false
            try { $done = $p.WaitForExit(12000) } catch { $done = $false }
            if (-not $done) { try { & taskkill.exe /PID $p.Id /T /F 2>$null | Out-Null } catch {} }
        }
    } catch {}
    $txt = ""
    $err = ""
    if (Test-Path -LiteralPath $outFile) { $txt = Get-Content -LiteralPath $outFile -Raw -ErrorAction SilentlyContinue }
    if (Test-Path -LiteralPath $errFile) { $err = Get-Content -LiteralPath $errFile -Raw -ErrorAction SilentlyContinue }
    Remove-Item -LiteralPath $outFile, $errFile -Force -ErrorAction SilentlyContinue
    $blob = (($txt + " " + $err) | Out-String)
    if ($blob -match '(?i)Permission denied') { return $true }
    if ($blob -match '(?i)No such file|Not a directory') { return $false }
    return [bool](($txt | Out-String).Trim())
}

function Restore-AdbStageIntoCase {
    param([string]$Original, [string]$LogPath = "", [string]$ProgressFile = "")
    $stageRoot = Get-AdbStageRoot
    if (-not (Test-Path -LiteralPath $stageRoot)) { return 0 }
    $destRoot = Join-Path $Original "adb_logical\filesystem\sdcard"
    New-Item -ItemType Directory -Force -Path $destRoot | Out-Null
    $n = 0
    Get-ChildItem -LiteralPath $stageRoot -Directory -ErrorAction SilentlyContinue | ForEach-Object {
        $dest = Join-Path $destRoot $_.Name
        $c = Invoke-AdbLinkOrCopy -Stage $_.FullName -FinalDir $dest -ProgressFile $ProgressFile
        $n += [int]$c
        Write-AcquireLog $LogPath ("Restored ADB staging {0}: {1} file(s)" -f $_.Name, $c)
    }
    return $n
}

function Invoke-AdbLinkOrCopy {
    param([string]$Stage, [string]$FinalDir, [string]$ProgressFile = "")
    New-Item -ItemType Directory -Force -Path $FinalDir | Out-Null
    $srcStats = Get-DirFileStats -Dir $Stage
    $dstStats = Get-DirFileStats -Dir $FinalDir
    if ([int]$srcStats.files -gt 0 -and [int]$dstStats.files -ge [int]$srcStats.files) {
        Write-AdbProgress -ProgressFile $ProgressFile -Remote $Stage -Files ([int]$dstStats.files) -Bytes ([int64]$dstStats.bytes)
        return [int]$dstStats.files
    }
    if ([int]$srcStats.files -gt 0 -and -not (Test-VolumeRoom -Path $FinalDir -MinBytes 1GB)) {
        $script:AdbDiskNote = ("Case volume has no free space. {0} file(s) stay in staging at {1}. Free space on the case drive, then retry so they can be copied into the case." -f $srcStats.files, $Stage)
        Write-AdbProgress -ProgressFile $ProgressFile -Remote $Stage -Files ([int]$srcStats.files) -Bytes ([int64]$srcStats.bytes)
        return [Math]::Max([int]$dstStats.files, [int]$srcStats.files)
    }
    $copied = Invoke-PyTreeJson -ExtraArgs @("--copy-src", $Stage, "--copy-dst", $FinalDir, "--progress", $ProgressFile)
    if ($copied -and [int]$copied.files -gt 0) { return [int]$copied.files }
    try {
        & robocopy.exe $Stage $FinalDir /E /COPY:DAT /R:1 /W:1 /NFL /NDL /NJH /NJS /nc /ns /np | Out-Null
    } catch {}
    return [int](Get-DirFileStats -Dir $FinalDir).files
}

function Invoke-AdbPullShort {
    param(
        $Adb,
        [string]$RemoteDir,
        [string]$FinalDir,
        [string]$LogPath,
        [string]$Tag,
        [string]$ProgressFile = "",
        [int]$IdleZeroSec = 35,
        [int]$MaxSec = 2400
    )
    $stageRoot = Get-AdbStageRoot
    $stage = Join-Path $stageRoot $Tag
    New-Item -ItemType Directory -Force -Path $stageRoot | Out-Null
    $remoteExists = Test-AdbRemoteExists -Adb $Adb -RemoteDir $RemoteDir
    $existing = 0
    if (Test-Path -LiteralPath $stage) {
        $existing = [int](Get-DirFileStats -Dir $stage).files
    }
    if ($existing -gt 5) {
        Write-AcquireLog $LogPath ("Reusing {0} file(s) already pulled for {1}" -f $existing, $RemoteDir)
        $nCopy = Invoke-AdbLinkOrCopy -Stage $stage -FinalDir $FinalDir -ProgressFile $ProgressFile
        Write-AdbProgress -ProgressFile $ProgressFile -Remote $RemoteDir -Files $existing -Bytes 0
        return [Math]::Max($existing, $nCopy)
    }
    if (-not $remoteExists) {
        Write-AcquireLog $LogPath ("Remote {0} is empty or missing - skipping pull." -f $RemoteDir)
        return 0
    }
    if ($RemoteDir -match '(?i)whatsapp' -and $IdleZeroSec -lt 180) { $IdleZeroSec = 180 }
    elseif ($IdleZeroSec -lt 45) { $IdleZeroSec = 90 }
    New-Item -ItemType Directory -Force -Path $stage | Out-Null
    $pullLog = Join-Path $stageRoot ($Tag + ".log")
    $pullErr = Join-Path $stageRoot ($Tag + ".err.log")
    Write-AcquireLog $LogPath ("adb pull {0} -> {1} (first file wait {2}s)" -f $RemoteDir, $stage, $IdleZeroSec)
    Write-AdbProgress -ProgressFile $ProgressFile -Remote $RemoteDir -Files 0 -Bytes 0
    $proc = $null
    try {
        $proc = Start-Process -FilePath $Adb -ArgumentList @("pull", $RemoteDir, $stage) -PassThru -NoNewWindow `
            -RedirectStandardOutput $pullLog -RedirectStandardError $pullErr
    } catch { $proc = $null }
    if (-not $proc) { return 0 }
    $started = Get-Date
    $lastFiles = 0
    $lastGrowth = Get-Date
    while (-not $proc.HasExited) {
        Start-Sleep -Seconds 3
        $st = Get-DirFileStats -Dir $stage
        Write-AdbProgress -ProgressFile $ProgressFile -Remote $RemoteDir -Files $st.files -Bytes $st.bytes
        if ([int]$st.files -gt $lastFiles) {
            $lastFiles = [int]$st.files
            $lastGrowth = Get-Date
        }
        $elapsed = ((Get-Date) - $started).TotalSeconds
        $idle = ((Get-Date) - $lastGrowth).TotalSeconds
        if ($lastFiles -eq 0 -and $idle -ge $IdleZeroSec) {
            Write-AcquireLog $LogPath ("adb pull {0} still 0 local files after {1}s (phone listing a large tree, or USB stall)." -f $RemoteDir, [int]$idle)
            try { & taskkill.exe /PID $proc.Id /T /F 2>$null | Out-Null } catch {}
            break
        }
        if ($elapsed -ge $MaxSec) {
            Write-AcquireLog $LogPath ("adb pull {0} hit {1}s cap with {2} file(s)." -f $RemoteDir, $MaxSec, $lastFiles)
            try { & taskkill.exe /PID $proc.Id /T /F 2>$null | Out-Null } catch {}
            break
        }
    }
    try { $proc.WaitForExit(5000) } catch {}
    $st = Get-DirFileStats -Dir $stage
    $n = [int]$st.files
    if ($n -gt 0) {
        $nCopy = Invoke-AdbLinkOrCopy -Stage $stage -FinalDir $FinalDir -ProgressFile $ProgressFile
        Write-AcquireLog $LogPath ("adb pull {0} copied {1} file(s) (case folder {2})" -f $RemoteDir, $n, $nCopy)
        Write-AdbProgress -ProgressFile $ProgressFile -Remote $RemoteDir -Files $n -Bytes $st.bytes
        return [Math]::Max($n, $nCopy)
    }
    $errTxt = ""
    if (Test-Path -LiteralPath $pullErr) { $errTxt = Get-Content -LiteralPath $pullErr -Raw -ErrorAction SilentlyContinue }
    Write-AcquireLog $LogPath ("adb pull {0} produced no files. {1}" -f $RemoteDir, (($errTxt -replace '\s+', ' ').Trim()))
    return 0
}


function Invoke-AdbDeviceStateDump {
    param($Adb, [string]$OutDir, [string]$LogPath)
    $stateDir = Join-Path $OutDir "device_state"
    New-Item -ItemType Directory -Force -Path $stateDir | Out-Null
    $cmds = @(
        @{ n = "getprop.txt"; a = @("shell", "getprop") },
        @{ n = "pm_packages_third_party.txt"; a = @("shell", "pm", "list", "packages", "-3") },
        @{ n = "id.txt"; a = @("shell", "id") },
        @{ n = "ls_sdcard.txt"; a = @("shell", "ls", "-la", "/sdcard") },
        @{ n = "ls_android_media.txt"; a = @("shell", "ls", "-la", "/sdcard/Android/media") }
    )
    foreach ($c in $cmds) {
        $out = Join-Path $stateDir $c.n
        $err = Join-Path $stateDir ($c.n + ".err")
        try {
            $proc = Start-Process -FilePath $Adb -ArgumentList $c.a -PassThru -NoNewWindow `
                -RedirectStandardOutput $out -RedirectStandardError $err
            if ($proc) {
                $done = $false
                try { $done = $proc.WaitForExit(15000) } catch { $done = $false }
                if (-not $done) { try { & taskkill.exe /PID $proc.Id /T /F 2>$null | Out-Null } catch {} }
            }
        } catch {}
    }
    Write-AcquireLog $LogPath "Wrote ADB device-state dumps (getprop, packages, mounts)."
}

function Invoke-AndroidAdbAcquire {
    param([string]$OutDir, [string]$LogPath, [string]$ProgressFile = "", [string]$WantedMethod = "full_file_system")
    $adb = Find-HostTool -Names @("adb.exe", "adb") -ExtraPaths @(
        (Join-Path (Get-RepoRoot) "tools\platform-tools\adb.exe"),
        "$env:LOCALAPPDATA\Android\Sdk\platform-tools\adb.exe",
        "$env:LOCALAPPDATA\Microsoft\WinGet\Links\adb.exe",
        "C:\Android\platform-tools\adb.exe",
        "C:\platform-tools\adb.exe"
    )
    if (-not $adb) {
        return @{ ok = $false; method = $null; error = "adb_not_found"; adb_state = "none"; app_private = $false }
    }
    Write-AcquireLog $LogPath ("Using adb: {0}" -f $adb)
    $adbState = Wait-AdbDevice -Adb $adb -LogPath $LogPath -Seconds 50
    if ($adbState -eq "unauthorized") {
        Write-AcquireLog $LogPath "adb unauthorized - unlock phone and tap Allow USB debugging. Falling back to MTP if available."
        return @{ ok = $false; method = "android_adb"; error = "adb_unauthorized_tap_allow_on_phone"; adb_state = "unauthorized"; app_private = $false }
    }
    if ($adbState -ne "device") {
        Write-AcquireLog $LogPath "adb saw no device. Enable Developer options > USB debugging, set USB to File transfer, tap Allow, then re-run. MTP can still copy shared storage."
        return @{ ok = $false; method = "android_adb"; error = "adb_no_device"; adb_state = "none"; app_private = $false }
    }
    Invoke-AdbDeviceStateDump -Adb $adb -OutDir $OutDir -LogPath $LogPath

    # Collect small private WhatsApp keys before the large shared-media copies.
    # The helper uses existing root/su or permitted run-as, never writes to the phone,
    # and rejects command errors saved as key files. JSON contains provenance only.
    $keyPython = Find-KitPython
    $keyReader = Join-Path (Get-RepoRoot) "backend\app\services\mobile_acquire\privileged_app_pull.py"
    if ($keyPython -and (Test-Path -LiteralPath $keyReader)) {
        $keyResult = Join-Path $OutDir "whatsapp_key_capture.json"
        $keyErrors = Join-Path $OutDir "whatsapp_key_capture.err.log"
        $priorKeyPythonPath = $env:PYTHONPATH
        $env:PYTHONPATH = Get-KitPythonPathEnv
        try {
            $keyArguments = @(('"' + $keyReader + '"'), "--adb", ('"' + $adb + '"'),
                "--out", ('"' + (Join-Path $OutDir "filesystem\private_keys") + '"'), "--keys-only")
            if ($ProgressFile) { $keyArguments += @("--progress", ('"' + $ProgressFile + '"')) }
            $keyProcess = Start-Process -FilePath $keyPython -ArgumentList $keyArguments -PassThru -NoNewWindow `
                -RedirectStandardOutput $keyResult -RedirectStandardError $keyErrors
            if (-not $keyProcess.WaitForExit(180000)) {
                & taskkill.exe /PID $keyProcess.Id /T /F 2>$null | Out-Null
                Write-AcquireLog $LogPath "WhatsApp key capture reached its time limit; any validated files already collected are retained."
            } elseif (Test-Path -LiteralPath $keyResult) {
                $keyInfo = Get-Content -LiteralPath $keyResult -Raw | ConvertFrom-Json
                Write-AcquireLog $LogPath ("WhatsApp key capture: {0} validated file(s). Intake derives the 64-character key from bytes 126-157 of a 158-byte key file." -f @($keyInfo.whatsapp_key_files).Count)
                foreach ($keyLimitation in @($keyInfo.limitations)) {
                    Write-AcquireLog $LogPath ([string]$keyLimitation)
                }
            }
        } catch {
            Write-AcquireLog $LogPath ("WhatsApp key capture could not complete: {0}" -f $_.Exception.Message)
        } finally {
            $env:PYTHONPATH = $priorKeyPythonPath
        }
    } else {
        Write-AcquireLog $LogPath "WhatsApp key reader unavailable. Upload an acquired key file in Intake."
    }

    $fsDir = Join-Path $OutDir "filesystem"
    $sharedDir = Join-Path $fsDir "sdcard"
    New-Item -ItemType Directory -Force -Path $sharedDir | Out-Null
    $sharedComplete = $false
    $seedStage = Get-DirFileStats -Dir (Get-AdbStageRoot)
    if ([int]$seedStage.files -gt 0) {
        Write-AdbProgress -ProgressFile $ProgressFile -Remote "reused staging" -Files ([int]$seedStage.files) -Bytes ([int64]$seedStage.bytes)
        Write-AcquireLog $LogPath ("Staging already has {0} file(s) / {1} byte(s) from earlier pulls." -f $seedStage.files, $seedStage.bytes)
    }

    # Short-path adb pull only. exec-out tar hung ~22 min with 0 files on this Galaxy.
    # List what is actually on the phone, pull those trees once, reuse evidence\_s.
    $mediaPkgs = @()
    try {
        $mediaPkgs = @((& $adb shell "ls /sdcard/Android/media" 2>$null) | ForEach-Object { ([string]$_).Trim() } | Where-Object { $_ })
    } catch { $mediaPkgs = @() }
    $priorityPkgs = @($mediaPkgs | Sort-Object {
        if ($_ -match '(?i)whatsapp') { "0$_" } elseif ($_ -match '(?i)telegram|instagram|facebook|snapchat|signal') { "1$_" } else { "2$_" }
    })
    $pullList = New-Object System.Collections.Generic.List[string]
    # Android Agent only. Legacy WhatsApp + scoped media + every top-level /sdcard
    # folder. iOS jobs never enter this function.
    foreach ($first in @(
        "/sdcard/WhatsApp",
        "/storage/emulated/0/WhatsApp",
        "/sdcard/Android/media/com.whatsapp",
        "/sdcard/Android/media/com.whatsapp.w4b",
        "/sdcard/Android/data/com.whatsapp",
        "/sdcard/Android/data/com.whatsapp.w4b",
        "/sdcard/WhatsApp/Media",
        "/sdcard/WhatsApp/Media/.Statuses",
        "/sdcard/Android/media/com.whatsapp/WhatsApp",
        "/sdcard/Android/media/com.whatsapp/WhatsApp/Media",
        "/sdcard/Android/media/com.whatsapp/WhatsApp/Databases",
        "/sdcard/DCIM",
        "/sdcard/DCIM/.trashed",
        "/sdcard/DCIM/.trash",
        "/sdcard/Pictures",
        "/sdcard/Pictures/.trashed",
        "/sdcard/Movies",
        "/sdcard/.Trash",
        "/sdcard/.trashed"
    )) {
        if (-not $pullList.Contains($first)) { $pullList.Add($first) | Out-Null }
    }
    foreach ($pkg in $priorityPkgs) {
        $remote = "/sdcard/Android/media/" + $pkg
        if (-not $pullList.Contains($remote)) { $pullList.Add($remote) | Out-Null }
    }
    $topDirs = @()
    try {
        $topDirs = @((& $adb shell "ls /sdcard" 2>$null) | ForEach-Object { ([string]$_).Trim() } | Where-Object { $_ -and $_ -notmatch '^(Android|\.|\.\.)$' })
    } catch { $topDirs = @() }
    if (-not $topDirs -or $topDirs.Count -eq 0) {
        $topDirs = @("DCIM", "Pictures", "Download", "Downloads", "Documents", "Movies", "Music", "Recordings", "Notifications", "Podcasts", "Telegram", "Ringtones", "Alarms", "Bluetooth")
    }
    foreach ($top in $topDirs) {
        $remote = "/sdcard/" + $top
        if (-not $pullList.Contains($remote)) { $pullList.Add($remote) | Out-Null }
    }
    if (-not $pullList.Contains("/sdcard/Android/data")) { $pullList.Add("/sdcard/Android/data") | Out-Null }
    Write-AcquireLog $LogPath ("Pulling {0} shared-storage tree(s) via short-path adb pull (no tar)." -f $pullList.Count)
    $pulledOk = New-Object System.Collections.Generic.List[string]
    foreach ($remote in $pullList) {
        $coveredBy = ""
        foreach ($done in $pulledOk) {
            $prefix = $done.TrimEnd('/') + '/'
            if ($remote.StartsWith($prefix)) { $coveredBy = $done; break }
        }
        if ($coveredBy) {
            Write-AcquireLog $LogPath ("Skipping {0} - already inside pulled tree {1}." -f $remote, $coveredBy)
            continue
        }
        $stageRootNow = Get-AdbStageRoot
        if (-not (Test-VolumeRoom -Path $stageRootNow -MinBytes 2GB)) {
            $script:AdbDiskNote = ("Stopped further phone copies because the staging volume has under 2 GB free ({0}). Files already copied are kept." -f $stageRootNow)
            Write-AcquireLog $LogPath $script:AdbDiskNote
            break
        }
        $tag = (($remote -replace '\\','/') -replace '[/:*?<>|"]','_').Trim('_')
        $dest = Join-Path $sharedDir $tag
        Write-AcquireLog $LogPath ("Pulling {0} (keep the phone unlocked)..." -f $remote)
        $maxSec = 2400
        if ($remote -match '(?i)whatsapp') { $maxSec = 3600 }
        $n = Invoke-AdbPullShort -Adb $adb -RemoteDir $remote -FinalDir $dest -LogPath $LogPath -Tag $tag -ProgressFile $ProgressFile -MaxSec $maxSec
        if ($n -gt 0) {
            $sharedComplete = $true
            $pulledOk.Add($remote) | Out-Null
        }
    }

    $appDataDir = Join-Path $OutDir "logical\app_data"
    New-Item -ItemType Directory -Force -Path $appDataDir | Out-Null
    $appPrivate = $false
    $smsOk = $false
    $ffsAttempted = $true

    $provCount = Invoke-AdbProviderDump -Adb $adb -OutDir $OutDir -LogPath $LogPath
    if ($provCount -gt 0) { $smsOk = $true }

    # Full file system: already-present su only. adb root on production Samsung
    # restarts adbd and wastes time; skip it unless the shell is already uid 0.
    $idOut = ""
    try { $idOut = (& $adb shell id 2>$null | Out-String) } catch { $idOut = "" }
    $isRootShell = ($idOut -match 'uid=0')
    $hasSu = $false
    if (-not $isRootShell) {
        $suFile = Join-Path $OutDir "su_id.txt"
        $suErr = Join-Path $OutDir "su_id.err.txt"
        try {
            $suProc = Start-Process -FilePath $adb -ArgumentList @("shell", "su", "-c", "id") -PassThru -NoNewWindow `
                -RedirectStandardOutput $suFile -RedirectStandardError $suErr
            if ($suProc) {
                $suDone = $false
                try { $suDone = $suProc.WaitForExit(8000) } catch { $suDone = $false }
                if (-not $suDone) { try { & taskkill.exe /PID $suProc.Id /T /F 2>$null | Out-Null } catch {} }
            }
        } catch {}
        $suOut = ""
        if (Test-Path -LiteralPath $suFile) { $suOut = Get-Content -LiteralPath $suFile -Raw -ErrorAction SilentlyContinue }
        $hasSu = ($suOut -match 'uid=0')
    }
    if ($isRootShell -or $hasSu) {
        Write-AcquireLog $LogPath "Device already has root/su. Collecting private app/system evidence read-only (no exploit, rooting or lock bypass is installed)."
        $privDir = Join-Path $fsDir "data"
        New-Item -ItemType Directory -Force -Path $privDir | Out-Null

        # adb pull cannot inherit su permissions. Use the bundled Python reader to
        # enumerate/cat already-readable private files one-by-one without creating
        # temporary files on the handset. This collects messaging/social app DBs,
        # their WAL/journals/keys, and system telephony/contact/calendar stores.
        $py = Find-KitPython
        $privPull = Join-Path (Get-RepoRoot) "backend\app\services\mobile_acquire\privileged_app_pull.py"
        if ($py -and (Test-Path -LiteralPath $privPull)) {
            $ppOut = Join-Path $OutDir "privileged_app_pull.json"
            $ppErr = Join-Path $OutDir "privileged_app_pull.err.log"
            $prevPy = $env:PYTHONPATH
            $env:PYTHONPATH = Get-KitPythonPathEnv
            try {
                $ppArgs = @(('"' + $privPull + '"'), "--adb", ('"' + $adb + '"'), "--out", ('"' + (Join-Path $privDir "private") + '"'))
                if ($ProgressFile) { $ppArgs += @("--progress", ('"' + $ProgressFile + '"')) }
                $pp = Start-Process -FilePath $py -ArgumentList $ppArgs -Wait -PassThru -NoNewWindow `
                    -RedirectStandardOutput $ppOut -RedirectStandardError $ppErr
                if (Test-Path -LiteralPath $ppOut) {
                    $ppRaw = Get-Content -LiteralPath $ppOut -Raw -ErrorAction SilentlyContinue
                    $ppObj = $null
                    try { $ppObj = $ppRaw | ConvertFrom-Json } catch {}
                    if ($ppObj -and [int]$ppObj.files -gt 0) {
                        $appPrivate = $true
                        Write-AcquireLog $LogPath ("Private app/system reader captured {0} file(s), {1} byte(s), root_mode={2}" -f $ppObj.files, $ppObj.bytes, $ppObj.root_mode)
                    } elseif ($ppObj -and $ppObj.limitations) {
                        Write-AcquireLog $LogPath (("Private reader limitation: " + (($ppObj.limitations | Select-Object -First 2) -join "; ")))
                    }
                }
            } catch {
                Write-AcquireLog $LogPath ("Private app/system reader failed: {0}" -f $_.Exception.Message)
            } finally {
                $env:PYTHONPATH = $prevPy
            }
        }

        # Keep the legacy direct pull as an additional fast path when adbd itself
        # is uid 0. It is expected to fail on normal production adbd + su.
        if ($isRootShell) {
            $nPriv = Invoke-AdbPullShort -Adb $adb -RemoteDir "/data/data" -FinalDir (Join-Path $privDir "data_data") `
                -LogPath $LogPath -Tag "data_data" -ProgressFile $ProgressFile -IdleZeroSec 20 -MaxSec 1800
            if ($nPriv -gt 0) { $appPrivate = $true }
        }
    } else {
        Write-AcquireLog $LogPath "Production build has no adb root/su. /data/data (plaintext WhatsApp msgstore.db and files/key) is not readable."
    }

    $backupWaitMs = 20000
    $waAb = Join-Path $OutDir "whatsapp.ab"
    Write-AcquireLog $LogPath "Trying adb backup for com.whatsapp (20s). Tap Back up my data if the phone shows it."
    $waProc = Start-Process -FilePath $adb -ArgumentList @("backup", "-f", $waAb, "-apk", "com.whatsapp") -PassThru -NoNewWindow
    if ($waProc) {
        $waDone = $false
        try { $waDone = $waProc.WaitForExit($backupWaitMs) } catch { $waDone = $false }
        if (-not $waDone) {
            Write-AcquireLog $LogPath "WhatsApp adb backup not confirmed on the phone - skipping (production WhatsApp usually sets allowBackup=false)."
            try { & taskkill.exe /PID $waProc.Id /T /F 2>$null | Out-Null } catch {}
        }
    }
    if (Test-Path -LiteralPath $waAb) {
        $waLen = (Get-Item -LiteralPath $waAb).Length
        Write-AcquireLog $LogPath ("WhatsApp adb backup file size: {0} byte(s)" -f $waLen)
        if ($waLen -gt 64) {
            Copy-Item -LiteralPath $waAb -Destination (Join-Path $appDataDir "whatsapp.ab") -Force -ErrorAction SilentlyContinue
            $extracted = Invoke-AdbExtractBackup -AbPath $waAb -DestDir (Join-Path $appDataDir "whatsapp_ab_extracted") -LogPath $LogPath
            if ($extracted -gt 0) { $appPrivate = $true }
        }
    }

    # Binary, exit-checked reader: errors must never become files/key or DBs.
    # The reader probes both WhatsApp and Business and collects every private
    # file only if Android already grants run-as for that installed build.
    $py = Find-KitPython
    $privPull = Join-Path (Get-RepoRoot) "backend\app\services\mobile_acquire\privileged_app_pull.py"
    if ($py -and (Test-Path -LiteralPath $privPull)) {
        $raOut = Join-Path $OutDir "debuggable_app_pull.json"
        $raErr = Join-Path $OutDir "debuggable_app_pull.err.log"
        $prevPy = $env:PYTHONPATH
        $env:PYTHONPATH = Get-KitPythonPathEnv
        try {
            $raArgs = @(('"' + $privPull + '"'), "--adb", ('"' + $adb + '"'), "--out", ('"' + (Join-Path $appDataDir "run_as_apps") + '"'), "--run-as")
            $ra = Start-Process -FilePath $py -ArgumentList $raArgs -Wait -PassThru -NoNewWindow `
                -RedirectStandardOutput $raOut -RedirectStandardError $raErr
            $raObj = $null
            if (Test-Path -LiteralPath $raOut) {
                try { $raObj = Get-Content -LiteralPath $raOut -Raw | ConvertFrom-Json } catch {}
            }
            if ($ra -and $ra.ExitCode -eq 0 -and $raObj -and [int]$raObj.files -gt 0) {
                $appPrivate = $true
                Write-AcquireLog $LogPath ("Verified run-as reader captured {0} private file(s)" -f $raObj.files)
            } elseif ($raObj -and $raObj.limitations) {
                Write-AcquireLog $LogPath (($raObj.limitations -join "; "))
            }
        } catch {
            Write-AcquireLog $LogPath ("Debuggable app reader failed: {0}" -f $_.Exception.Message)
        } finally {
            $env:PYTHONPATH = $prevPy
        }
    }

    $countStats = Get-DirFileStats -Dir $OutDir
    $count = [int]$countStats.files
    $ok = ($count -gt 0)
    $sharedComplete = ($sharedComplete -and $count -gt 80)
    $selectedMethod = "adb_android_logical"
    if ($appPrivate) { $selectedMethod = "adb_android_full_file_system" }
    elseif ($sharedComplete) { $selectedMethod = "adb_android_file_system" }
    Write-AcquireLog $LogPath ("adb Android acquire finished: {0} file(s), app_private={1}, sms_providers={2}, shared_complete={3}" -f $count, $appPrivate, $smsOk, $sharedComplete)
    return @{
        ok               = $ok
        method           = $selectedMethod
        files_copied     = $count
        error            = $(if ($ok) { "" } else { "adb_pull_and_backup_failed" })
        adb_state        = "device"
        app_private      = [bool]$appPrivate
        sms_ok           = [bool]$smsOk
        shared_complete  = [bool]$sharedComplete
        ffs_attempted    = [bool]$ffsAttempted
        disk_note        = [string]$script:AdbDiskNote
    }
}

function Test-CanonicalIosUdid {
    param([string]$Value)
    return [bool]($Value -match '^[0-9A-Fa-f]{8}-[0-9A-Fa-f]{16}$' -or $Value -match '^[0-9A-Fa-f]{40}$')
}

function ConvertTo-IosUdid {
    param([string]$Value)
    if (-not $Value) { return "" }
    $v = $Value.Trim()
    if (Test-CanonicalIosUdid $v) { return $v }
    $hex = ""
    if ($v -match '#([0-9A-Fa-f]{24}|[0-9A-Fa-f]{40})(?:[&#?]|$)') {
        $hex = $Matches[1]
    } else {
        $m = [regex]::Match($v, '([0-9A-Fa-f]{24}|[0-9A-Fa-f]{40})\s*$')
        if ($m.Success) { $hex = $m.Groups[1].Value }
    }
    if ($hex.Length -eq 24) { return ($hex.Substring(0, 8) + "-" + $hex.Substring(8)) }
    if ($hex.Length -eq 40) { return $hex }
    return ""
}

function Invoke-IosToolAcquire {
    param(
        [string]$OutDir,
        [string]$LogPath,
        [string]$Udid = "",
        [string]$ProgressFile = "",
        [string]$RunName = "",
        [string]$Stamp = ""
    )
    $mdsPresent = Test-AppleMobileDeviceSupport
    if (-not $mdsPresent) {
        Write-AcquireLog $LogPath "Apple Mobile Device Support folder/service not found. Trying usbmux via pymobiledevice3 anyway (WPD/MTP is not a substitute for iTunes backup)."
    }

    $toolDir = Join-Path (Get-RepoRoot) "tools\libimobiledevice"
    $idevice = Find-HostTool -Names @("idevicebackup2.exe", "idevicebackup2") -ExtraPaths @(
        (Join-Path $toolDir "idevicebackup2.exe"),
        "C:\Program Files\libimobiledevice\idevicebackup2.exe",
        "C:\tools\libimobiledevice\idevicebackup2.exe"
    )
    $ideviceId = Find-HostTool -Names @("idevice_id.exe", "idevice_id") -ExtraPaths @(Join-Path $toolDir "idevice_id.exe")
    $idevicePair = Find-HostTool -Names @("idevicepair.exe", "idevicepair") -ExtraPaths @(Join-Path $toolDir "idevicepair.exe")
    $ideviceInfo = Find-HostTool -Names @("ideviceinfo.exe", "ideviceinfo") -ExtraPaths @(Join-Path $toolDir "ideviceinfo.exe")

    $usePymobileBackup = -not $idevice
    if ($usePymobileBackup) {
        Write-AcquireLog $LogPath "idevicebackup2 not found; will use examiner-kit pymobiledevice3 backup after UDID resolve."
    } else {
        Write-AcquireLog $LogPath ("Using idevicebackup2: {0}" -f $idevice)
    }

    # Resolve UDID from Apple usbmux (pymobiledevice3) or idevice_id.
    # Windows WPD/Apple driver ids (USB#VID_...#SERIAL) are not lockdown UDIDs.
    $fromWindows = ConvertTo-IosUdid $Udid
    $resolved = ""
    $listScript = Join-Path (Get-RepoRoot) "scripts\ios_usbmux_list.py"
    $py = Find-KitPython
    if ((Test-Path -LiteralPath $listScript) -and $py) {
        try {
            $prev = $env:PYTHONPATH
            $env:PYTHONPATH = Get-KitPythonPathEnv
            $raw = & $py $listScript 2>$null | Out-String
            $env:PYTHONPATH = $prev
            $obj = ($raw -split "`r?`n" | Where-Object { $_.Trim().StartsWith("{") } | Select-Object -Last 1) | ConvertFrom-Json
            $hintKey = ($fromWindows -replace '[^0-9A-Fa-f]', '').ToLowerInvariant()
            foreach ($dev in @($obj.devices)) {
                $uid = [string]$dev.udid
                $key = ($uid -replace '[^0-9A-Fa-f]', '').ToLowerInvariant()
                if (-not $uid) { continue }
                if (-not $hintKey -or $key -eq $hintKey -or $key.EndsWith($hintKey) -or $hintKey.EndsWith($key)) {
                    $resolved = $uid
                    break
                }
            }
            if (-not $resolved) {
                $first = @($obj.devices) | Select-Object -First 1
                if ($first -and $first.udid) { $resolved = [string]$first.udid }
            }
        } catch { }
    }
    if (-not $resolved -and $ideviceId) {
        try {
            $listOut = & $ideviceId -l 2>&1 | Out-String
            $match = [regex]::Match($listOut, "[0-9A-Fa-f]{8}-[0-9A-Fa-f]{16}|[0-9A-Fa-f]{40}")
            if ($match.Success) { $resolved = $match.Value }
        }
        catch { }
    }
    if ($resolved) { $Udid = $resolved }
    elseif ($fromWindows) { $Udid = $fromWindows }
    if (-not (Test-CanonicalIosUdid $Udid)) {
        if (-not $mdsPresent) {
            Write-AcquireLog $LogPath "No iPhone UDID via usbmux. Apple Mobile Device Support is not installed - iTunes-style backup cannot start. WPD/MTP Internal Storage copy is skipped because it hangs with 0 files."
            return @{
                ok     = $false
                method = $null
                error  = "apple_mobile_device_support_missing_install_via_winget_Apple.AppleMobileDeviceSupport"
            }
        }
        Write-AcquireLog $LogPath "No iPhone UDID via usbmux. Unlock phone, Trust This Computer, ensure Apple Mobile Device Service is running."
        return @{ ok = $false; method = $null; error = "ios_device_not_visible_unlock_and_trust_this_computer" }
    }
    Write-AcquireLog $LogPath ("iPhone UDID: {0}" -f $Udid)

    if ($ideviceInfo) {
        try {
            $name = & $ideviceInfo -u $Udid -k DeviceName 2>$null
            $ptype = & $ideviceInfo -u $Udid -k ProductType 2>$null
            $iosVer = & $ideviceInfo -u $Udid -k ProductVersion 2>$null
            Write-AcquireLog $LogPath ("Device info: name={0} type={1} ios={2}" -f $name, $ptype, $iosVer)
        }
        catch {
            Write-AcquireLog $LogPath ("ideviceinfo warning: {0}" -f $_.Exception.Message)
        }
    }

    $iosSizing = Get-IosDiskSizing -Udid $Udid -IdeviceInfo $ideviceInfo
    Write-AcquireLog $LogPath ("iOS storage preflight: used={0} GB required_free={1} GB" -f `
        [math]::Round(([int64]$iosSizing.used) / 1GB, 1), [math]::Round(([int64]$iosSizing.required) / 1GB, 1))

    if ($idevicePair) {
        Write-AcquireLog $LogPath "Validating USB pairing (enter passcode on iPhone if prompted)..."
        $pairValidate = Start-Process -FilePath $idevicePair -ArgumentList @("-u", $Udid, "validate") -Wait -PassThru -NoNewWindow -RedirectStandardError (Join-Path $OutDir "pair_validate.err") -RedirectStandardOutput (Join-Path $OutDir "pair_validate.out")
        if ($pairValidate.ExitCode -ne 0) {
            Write-AcquireLog $LogPath "Pair validate failed - attempting pair..."
            $pair = Start-Process -FilePath $idevicePair -ArgumentList @("-u", $Udid, "pair") -Wait -PassThru -NoNewWindow -RedirectStandardError (Join-Path $OutDir "pair.err") -RedirectStandardOutput (Join-Path $OutDir "pair.out")
            $pairErr = ""
            if (Test-Path -LiteralPath (Join-Path $OutDir "pair.err")) {
                $pairErr = (Get-Content -LiteralPath (Join-Path $OutDir "pair.err") -Raw -ErrorAction SilentlyContinue)
            }
            if ($pair.ExitCode -ne 0) {
                Write-AcquireLog $LogPath ("idevicepair failed: {0}" -f $pairErr)
                $hint = "ios_pair_failed_unlock_enter_passcode_and_trust_this_computer"
                if ($pairErr -match "passcode") { $hint = "ios_pair_needs_passcode_on_device" }
                elseif ($pairErr -match "trust|User denied") { $hint = "ios_pair_needs_trust_this_computer" }
                return @{ ok = $false; method = "idevicebackup2"; error = $hint; exit = $pair.ExitCode }
            }
            # Re-validate after pair dialog
            $pairValidate = Start-Process -FilePath $idevicePair -ArgumentList @("-u", $Udid, "validate") -Wait -PassThru -NoNewWindow
            if ($pairValidate.ExitCode -ne 0) {
                return @{ ok = $false; method = "idevicebackup2"; error = "ios_pair_not_validated_unlock_and_retry"; exit = $pairValidate.ExitCode }
            }
        }
        Write-AcquireLog $LogPath "USB pairing OK."
    }

    # iTunes-style full backup = UFED "Advanced Logical" equivalent (app containers / WhatsApp DBs when unencrypted or password known).
    $backupRoot = Join-Path $OutDir "ios_image"
    New-Item -ItemType Directory -Force -Path $backupRoot | Out-Null
    $udidBackup = Join-Path $backupRoot $Udid

    # Reuse a completed backup image if present in THIS job or ANY prior acquisition for same UDID.
    if ($env:IOS_ALLOW_REUSE_BACKUP -eq "1" -and -not $env:IOS_FORCE_REBACKUP) {
        $found = Find-ExistingIosBackupForUdid -Udid $Udid -PreferUnder $OutDir
        if ($found -and $found.path) {
            $existing = [string]$found.path
            # Ensure this job folder has a path pointing at the image (junction when from another job).
            if ($existing -ne $udidBackup) {
                $linked = Link-IosBackupIntoJob -SourceBackup $existing -DestBackup $udidBackup -LogPath $LogPath
                if ($linked) { $existing = $udidBackup }
            }
            $fileCount = [int]$found.files
            if ($fileCount -le 0) {
                $fileCount = @(Get-ChildItem -LiteralPath $existing -Recurse -File -ErrorAction SilentlyContinue).Count
            }
            Write-AcquireLog $LogPath ("Reusing existing iOS backup image at {0} (files={1}). Set IOS_FORCE_REBACKUP=1 to redo." -f $existing, $fileCount)
            return @{
                ok           = $true
                method       = "idevicebackup2"
                backup_path  = $existing
                files_copied = $fileCount
                reused       = $true
            }
        }
    }

    # PasswordProtected=true means a passcode is configured, not that the screen
    # is locked now. Aborting here skipped backup on every modern iPhone.
    if ($ideviceInfo) {
        try {
            $passcodeSet = (& $ideviceInfo -u $Udid -k PasswordProtected 2>$null | Out-String).Trim()
            if ($passcodeSet -match '^(?i)true$') {
                Write-AcquireLog $LogPath 'PasswordProtected=true (passcode configured). That is normal - attempting backup.'
            }
        }
        catch { }
    }

    if ($usePymobileBackup) {
        return Invoke-IosPymobileBackup -OutDir $OutDir -LogPath $LogPath -Udid $Udid -BackupRoot $backupRoot `
            -ProgressFile $ProgressFile -RunName $RunName -Stamp $Stamp -RequiredFreeBytes ([int64]$iosSizing.required)
    }

    Write-AcquireLog $LogPath ("Starting full iOS backup image into {0} (this can take a long time)..." -f $backupRoot)
    $backupArgs = @("-u", $Udid, "backup", "--full", $backupRoot)
    $proc = Start-Process -FilePath $idevice -ArgumentList $backupArgs -Wait -PassThru -NoNewWindow `
        -RedirectStandardError (Join-Path $OutDir "backup.err") `
        -RedirectStandardOutput (Join-Path $OutDir "backup.out")

    $backupDir = $backupRoot
    $hasManifest = Test-IosBackupComplete -Path $backupDir
    if (-not $hasManifest) {
        # idevicebackup2 usually writes <root>/<UDID>/Manifest.db (iOS 10+) or Manifest.plist
        $nested = Get-ChildItem -LiteralPath $backupRoot -Directory -ErrorAction SilentlyContinue |
            Where-Object { Test-IosBackupComplete -Path $_.FullName } |
            Select-Object -First 1
        if ($nested) {
            $hasManifest = $true
            $backupDir = $nested.FullName
        }
    }

    if ($hasManifest) {
        $fileCount = @(Get-ChildItem -LiteralPath $backupDir -Recurse -File -ErrorAction SilentlyContinue).Count
        $bytes = [int64]0
        Get-ChildItem -LiteralPath $backupDir -Recurse -File -ErrorAction SilentlyContinue | ForEach-Object { $bytes += $_.Length }
        Write-AcquireLog $LogPath ("iOS backup image ready: path={0} files={1} bytes={2}" -f $backupDir, $fileCount, $bytes)
        return @{
            ok           = $true
            method       = "idevicebackup2"
            backup_path  = $backupDir
            files_copied = $fileCount
            bytes        = $bytes
        }
    }

    $errTail = ""
    if (Test-Path -LiteralPath (Join-Path $OutDir "backup.err")) {
        $errTail = (Get-Content -LiteralPath (Join-Path $OutDir "backup.err") -Raw -ErrorAction SilentlyContinue)
        if ($errTail.Length -gt 800) { $errTail = $errTail.Substring(0, 800) }
    }
    $outTail = ""
    if (Test-Path -LiteralPath (Join-Path $OutDir "backup.out")) {
        $outTail = (Get-Content -LiteralPath (Join-Path $OutDir "backup.out") -Raw -ErrorAction SilentlyContinue)
        if ($outTail.Length -gt 1200) { $outTail = $outTail.Substring([Math]::Max(0, $outTail.Length - 1200)) }
    }
    $combined = "$errTail`n$outTail"
    Write-AcquireLog $LogPath ("Backup failed/missing Manifest.db or Manifest.plist exit={0} detail={1}" -f $proc.ExitCode, ($combined -replace '\s+', ' ').Trim())
    $errCode = "ios_backup_missing_manifest"
    if ($combined -match "ErrorCode 208|Device locked|MBErrorDomain/208") {
        $errCode = "ios_backup_device_locked_unlock_screen_keep_awake_and_retry"
    }
    elseif ($combined -match "encrypted|password") { $errCode = "ios_backup_encryption_or_password_issue" }
    elseif ($combined -match "protocol version exchange") { $errCode = "ios_backup_protocol_failed_retry_or_use_itunes_ufed" }
    return @{ ok = $false; method = "idevicebackup2"; error = $errCode; exit = $proc.ExitCode; detail = $combined }
}

function Invoke-IosPymobileBackup {
    param(
        [string]$OutDir,
        [string]$LogPath,
        [string]$Udid,
        [string]$BackupRoot,
        [string]$ProgressFile = "",
        [string]$RunName = "",
        [string]$Stamp = "",
        [int64]$RequiredFreeBytes = 0
    )
    $py = Find-IosKitPython
    $scriptPath = Join-Path (Get-RepoRoot) "scripts\ios_usbmux_backup.py"
    if (-not $py -or -not (Test-Path -LiteralPath $scriptPath)) {
        Write-AcquireLog $LogPath "Examiner kit python or ios_usbmux_backup.py missing."
        return @{ ok = $false; method = $null; error = "examiner_kit_python_missing_run_ensure_examiner_kit" }
    }
    if (-not $Stamp) { $Stamp = Get-Date -Format "yyyyMMdd_HHmmss" }
    Write-AcquireLog $LogPath ("Starting pymobiledevice3 backup dest={0} python={1} stamp={2}" -f $BackupRoot, $py, $Stamp)
    $errFile = Join-Path $OutDir "backup.err"
    $outFile = Join-Path $OutDir "backup.out"
    $prevPy = $env:PYTHONPATH
    $env:PYTHONPATH = Get-KitPythonPathEnv
    $backupArgs = @($scriptPath, "--udid", $Udid, "--dest", $BackupRoot, "--stamp", $Stamp)
    if ($RequiredFreeBytes -gt 0) { $backupArgs += @("--required-free-bytes", [string]$RequiredFreeBytes) }
    $proc = Start-Process -FilePath $py -ArgumentList $backupArgs `
        -PassThru -NoNewWindow -RedirectStandardError $errFile -RedirectStandardOutput $outFile
    $env:PYTHONPATH = $prevPy
    $cancel = ""
    if ($ProgressFile) { $cancel = $ProgressFile + ".cancel" }
    $stagingPath = ""
    $liveFiles = [int64]0
    $liveBytes = [int64]0
    $liveNewest = ""
    $lastScan = Get-Date
    $lastScan = $lastScan.AddSeconds(-20)
    while ($proc -and -not $proc.HasExited) {
        if ($cancel -and (Test-Path -LiteralPath $cancel)) {
            Write-AcquireLog $LogPath "Cancel file seen - stopping iPhone backup."
            & taskkill.exe /PID $proc.Id /T /F 2>$null | Out-Null
            break
        }
        $pct = 0.0
        if (Test-Path -LiteralPath $outFile) {
            $head = Get-Content -LiteralPath $outFile -TotalCount 12 -ErrorAction SilentlyContinue
            $tail = Get-Content -LiteralPath $outFile -Tail 40 -ErrorAction SilentlyContinue
            foreach ($line in @($head + $tail)) {
                if (-not $stagingPath -and $line -match '"dest"\s*:\s*"([^"]+)"') {
                    $cand = $Matches[1] -replace '\\\\', '\'
                    if ($cand -and (Test-Path -LiteralPath $cand)) { $stagingPath = $cand }
                }
                if ($line -match '"progress"\s*:\s*([0-9.]+)') {
                    try { $pct = [double]$Matches[1] } catch {}
                }
            }
        }
        if (-not $stagingPath -and $Stamp) {
            foreach ($letter in @("F", "D", "C", "E")) {
                $ib = "${letter}:\ib"
                if (-not (Test-Path -LiteralPath $ib)) { continue }
                Get-ChildItem -LiteralPath $ib -Directory -ErrorAction SilentlyContinue | ForEach-Object {
                    $cand = Join-Path $_.FullName $Stamp
                    if ((-not $stagingPath) -and (Test-Path -LiteralPath $cand)) { $stagingPath = $cand }
                }
            }
        }
        $now = Get-Date
        if ($stagingPath -and (($now - $lastScan).TotalSeconds -ge 8)) {
            $stats = Get-FolderLiveStats -Path $stagingPath
            $liveFiles = [int64]$stats.files
            $liveBytes = [int64]$stats.bytes
            $liveNewest = [string]$stats.newest
            $lastScan = $now
        }
        if ($ProgressFile) {
            try {
                $pctShown = [int][math]::Round($pct)
                $gb = [math]::Round($liveBytes / 1GB, 2)
                $detailText = "iPhone backup $pctShown% - $gb GB, $liveFiles files - keep the phone unlocked, screen awake, and Trust This Computer."
                $itemText = $liveNewest
                if (-not $itemText) { $itemText = "ios_backup" }
                $progObj = @{
                    stage         = "acquire"
                    item          = $itemText
                    category      = "Collecting"
                    detail        = $detailText
                    progress_pct  = [math]::Round(5 + ([math]::Max(0, [math]::Min(100, $pct)) * 0.60), 1)
                    phase         = "ios_backup"
                    phase_progress_pct = [math]::Round($pct, 1)
                    progress_mode = "bytes"
                    bytes_done    = $liveBytes
                    files_seen    = $liveFiles
                    run_name      = $RunName
                    output_path   = $(if ($stagingPath) { $stagingPath } else { $BackupRoot })
                    media_path    = $BackupRoot
                }
                $progObj | ConvertTo-Json -Compress | Set-Content -LiteralPath $ProgressFile -Encoding UTF8
            } catch {}
        }
        Start-Sleep -Seconds 2
    }
    if ($proc -and -not $proc.HasExited) {
        try { $proc.WaitForExit() } catch {}
    }
    $outTail = ""
    if (Test-Path -LiteralPath $outFile) {
        $outTail = Get-Content -LiteralPath $outFile -Raw -ErrorAction SilentlyContinue
    }
    $errTail = ""
    if (Test-Path -LiteralPath $errFile) {
        $errTail = Get-Content -LiteralPath $errFile -Raw -ErrorAction SilentlyContinue
    }
    $jsonLine = ($outTail -split "`r?`n" | Where-Object { $_.Trim().StartsWith("{") -and $_.Trim() -match '"ok"' } | Select-Object -Last 1)
    $backupDir = $null
    $failType = ""
    $failError = ""
    if ($jsonLine) {
        try {
            $obj = $jsonLine | ConvertFrom-Json
            if ($obj.ok -and $obj.backup_path) { $backupDir = [string]$obj.backup_path }
            if (-not $obj.ok) {
                $failType = [string]$obj.type
                $failError = [string]$obj.error
            }
        } catch { }
    }
    if (-not $backupDir) {
        $nested = Get-ChildItem -LiteralPath $BackupRoot -Directory -ErrorAction SilentlyContinue |
            Where-Object { Test-IosBackupComplete -Path $_.FullName } |
            Select-Object -First 1
        if ($nested) { $backupDir = $nested.FullName }
    }
    if ($backupDir -and (Test-IosBackupComplete -Path $backupDir)) {
        $wanted = Join-Path $BackupRoot ([IO.Path]::GetFileName($backupDir.TrimEnd('\', '/')))
        if ($wanted -and $backupDir -ne $wanted) {
            $linked = Link-IosBackupIntoJob -SourceBackup $backupDir -DestBackup $wanted -LogPath $LogPath
            if ($linked) { $backupDir = $wanted }
        }
        $fileCount = @(Get-ChildItem -LiteralPath $backupDir -Recurse -File -ErrorAction SilentlyContinue).Count
        $bytes = [int64]0
        Get-ChildItem -LiteralPath $backupDir -Recurse -File -ErrorAction SilentlyContinue | ForEach-Object { $bytes += $_.Length }
        Write-AcquireLog $LogPath ("iOS backup image ready (pymobiledevice3): path={0} files={1} bytes={2}" -f $backupDir, $fileCount, $bytes)
        return @{
            ok           = $true
            method       = "pymobiledevice3"
            backup_path  = $backupDir
            files_copied = $fileCount
            bytes        = $bytes
        }
    }
    $exitCode = 1
    if ($proc) { $exitCode = [int]$proc.ExitCode }
    $combined = "$failType $failError $errTail $outTail"
    $shortDetail = (($failType + " " + $failError).Trim())
    if (-not $shortDetail) { $shortDetail = (($combined -replace '\s+', ' ').Trim()) }
    if ($shortDetail.Length -gt 400) { $shortDetail = $shortDetail.Substring($shortDetail.Length - 400) }
    Write-AcquireLog $LogPath ("pymobiledevice3 backup failed exit={0} detail={1}" -f $exitCode, $shortDetail)
    $errCode = "ios_backup_incomplete_no_manifest_usb_may_have_dropped"
    if ($failType -match 'not_enough_disk|NotEnoughDiskSpace' -or $failError -match 'not_enough_disk|NotEnoughDiskSpace' -or $combined -match "NotEnoughDiskSpace|ios_backup_not_enough_disk_space|no space left") {
        $errCode = "ios_backup_not_enough_disk_space"
    }
    elseif ($failType -match 'ConnectionTerminated|ConnectionAborted|BrokenPipe|MuxException|ConnectionReset' -or $combined -match "ConnectionTerminatedError") {
        $errCode = "ios_backup_usb_connection_dropped_unlock_keep_awake_retry"
    }
    elseif ($combined -match "ErrorCode 208|Device locked|MBErrorDomain/208|PasswordRequired") {
        $errCode = "ios_backup_device_locked_unlock_screen_keep_awake_and_retry"
    }
    elseif ($combined -match "path_too_long|ios_backup_windows_path_too_long") {
        $errCode = "ios_backup_windows_path_too_long_retry_on_short_staging"
    }
    elseif ($combined -match "Pairing|NotPaired|trust") { $errCode = "ios_pair_failed_unlock_enter_passcode_and_trust_this_computer" }
    elseif ($combined -match "win32security|pywin32") { $errCode = "examiner_kit_missing_pywin32" }
    elseif ($failType -eq "ios_backup_incomplete" -or $failError -match "ios_backup_incomplete") {
        $errCode = "ios_backup_incomplete_no_manifest_usb_may_have_dropped"
    }
    return @{ ok = $false; method = "pymobiledevice3"; error = $errCode; exit = $exitCode; detail = $shortDetail }
}

function Move-IosStageIntoCase {
    param(
        [Parameter(Mandatory = $true)][string]$Stage,
        [Parameter(Mandatory = $true)][string]$OutDir,
        [string]$LogPath = ""
    )
    if (-not (Test-Path -LiteralPath $Stage)) { return @{ ok = $false; error = "stage_missing" } }

    $external = $false
    $stageRoot = [IO.Path]::GetPathRoot($Stage)
    $outRoot = [IO.Path]::GetPathRoot($OutDir)
    if ($Stage -match '^[A-Za-z]:\\ib\\' -and $stageRoot -and $outRoot -and ($stageRoot -ine $outRoot)) {
        try {
            $relative = ($Stage -replace '^[A-Za-z]:\\ib\\', '')
            $stableBase = Join-Path $stageRoot "Aetheris_Mobile_Payloads"
            $stableStage = Join-Path $stableBase $relative
            New-Item -ItemType Directory -Force -Path (Split-Path -Parent $stableStage) | Out-Null
            if (Test-Path -LiteralPath $stableStage) {
                $stableStage = $stableStage + "_" + [guid]::NewGuid().ToString("N").Substring(0,8)
            }
            Move-Item -LiteralPath $Stage -Destination $stableStage -Force -ErrorAction Stop
            $Stage = $stableStage
            $external = $true
            (@{
                case_path = $OutDir
                payload_path = $stableStage
                type = "ios_afc_house_arrest"
                complete = $true
            } | ConvertTo-Json -Depth 4) | Set-Content -LiteralPath (Join-Path $OutDir "EXTERNAL_AFC_PAYLOAD.json") -Encoding UTF8
            if ($LogPath) { Write-AcquireLog $LogPath ("Relocated temporary AFC payload out of X:\ib: {0}" -f $stableStage) }
        } catch {
            if ($LogPath) { Write-AcquireLog $LogPath ("Failed to relocate AFC staging: {0}" -f $_.Exception.Message) }
            return @{ ok = $false; error = "afc_stage_relocation_failed" }
        }
    }

    $moved = 0
    foreach ($name in @("afc_media", "house_arrest")) {
        $src = Join-Path $Stage $name
        $dst = Join-Path $OutDir $name
        if (-not (Test-Path -LiteralPath $src)) { continue }
        if (Test-Path -LiteralPath $dst) {
            $existing = Get-Item -LiteralPath $dst -Force -ErrorAction SilentlyContinue
            if ($existing -and ($existing.Attributes -band [IO.FileAttributes]::ReparsePoint)) {
                try { cmd.exe /c "rmdir `"$dst`"" | Out-Null } catch {}
            } else {
                Remove-Item -LiteralPath $dst -Recurse -Force -ErrorAction SilentlyContinue
            }
        }
        if ($external) {
            $linkOut = cmd.exe /c "mklink /J `"$dst`" `"$src`"" 2>&1 | Out-String
            if (-not (Test-Path -LiteralPath $dst)) {
                if ($LogPath) { Write-AcquireLog $LogPath ("AFC junction failed for {0}: {1}" -f $name, $linkOut.Trim()) }
                return @{ ok = $false; error = ("afc_junction_failed_{0}" -f $name) }
            }
            $moved++
            if ($LogPath) { Write-AcquireLog $LogPath ("Linked case {0} to stable payload: {1}" -f $name, $src) }
            continue
        }
        try {
            Move-Item -LiteralPath $src -Destination $dst -Force -ErrorAction Stop
            $moved++
            if ($LogPath) { Write-AcquireLog $LogPath ("Committed iOS {0} into case folder: {1}" -f $name, $dst) }
        } catch {
            New-Item -ItemType Directory -Force -Path $dst | Out-Null
            $rc = Start-Process -FilePath "robocopy.exe" -ArgumentList @($src, $dst, "/E", "/MOVE", "/COPY:DAT", "/DCOPY:DAT", "/R:2", "/W:2", "/XJ", "/NFL", "/NDL", "/NP") -Wait -PassThru -NoNewWindow
            if ($rc.ExitCode -ge 8) {
                return @{ ok = $false; error = ("robocopy_failed_{0}_{1}" -f $name, $rc.ExitCode) }
            }
            $moved++
            if ($LogPath) { Write-AcquireLog $LogPath ("Copied/moved iOS {0} into case folder: {1}" -f $name, $dst) }
        }
    }
    if (-not $external) {
        try {
            if (Test-Path -LiteralPath $Stage) { Remove-Item -LiteralPath $Stage -Recurse -Force -ErrorAction SilentlyContinue }
            $parent = Split-Path -Parent $Stage
            if ($parent -and (Test-Path -LiteralPath $parent) -and -not (Get-ChildItem -LiteralPath $parent -Force -ErrorAction SilentlyContinue)) {
                Remove-Item -LiteralPath $parent -Force -ErrorAction SilentlyContinue
            }
        } catch {}
    }
    return @{ ok = ($moved -gt 0); moved = $moved; external = $external; payload_path = $Stage }
}

function Invoke-IosAfcAcquire {
    <#
    iOS Agent only. Pulls AFC shared media + WhatsApp house_arrest after the
    iTunes backup. Android jobs must not call this.
    #>
    param(
        [string]$OutDir,
        [string]$LogPath,
        [string]$Udid,
        [string]$ProgressFile = "",
        [string]$Stamp = "",
        [int64]$BackupBytes = 0,
        [int]$BackupFiles = 0
    )
    $py = Find-IosKitPython
    $scriptPath = Join-Path (Get-RepoRoot) "scripts\ios_usbmux_afc.py"
    if (-not $py -or -not (Test-Path -LiteralPath $scriptPath)) {
        Write-AcquireLog $LogPath "ios_usbmux_afc.py or kit python missing - skipping AFC/house_arrest."
        return @{ ok = $false; error = "ios_afc_script_missing"; files = 0 }
    }
    if (-not $Stamp) { $Stamp = Get-Date -Format "yyyyMMdd_HHmmss" }
    $tail = ""
    if ($Udid) { $tail = ($Udid -replace '[^A-Fa-f0-9]', '') }
    if ($tail.Length -gt 8) { $tail = $tail.Substring($tail.Length - 8) }
    if (-not $tail) { $tail = "ios" }
    $stage = $null
    $afcNeed = [Math]::Max([int64](20GB), [int64]($BackupBytes * 0.50) + [int64](10GB))
    $drive = Get-IosStagingDrive -MinFreeBytes $afcNeed
    if ($drive -and $drive.Letter) {
        $ibRoot = Join-Path ($drive.Letter + ":") "ib"
        $stage = Join-Path (Join-Path $ibRoot $tail) ($Stamp + "_afc")
        New-Item -ItemType Directory -Force -Path $stage | Out-Null
        Write-AcquireLog $LogPath ("iOS AFC staging on {0}: free={1} GB" -f $drive.Letter, [math]::Round($drive.Free / 1GB, 1))
    }
    if (-not $stage) {
        $fallbackStage = Join-Path $OutDir "_afc_stage"
        $fallbackFree = [int64]-1
        try { $fallbackFree = [int64](Get-PSDrive -Name ([IO.Path]::GetPathRoot($OutDir).Substring(0,1)) -PSProvider FileSystem -ErrorAction Stop).Free } catch { }
        if ($fallbackFree -lt $afcNeed) {
            Write-AcquireLog $LogPath ("AFC storage preflight failed: required={0} GB best volume does not fit." -f [math]::Round($afcNeed/1GB,1))
            return @{ ok = $false; error = "ios_afc_not_enough_disk_space"; files = 0; required_free_bytes = $afcNeed }
        }
        $stage = $fallbackStage
    }
    New-Item -ItemType Directory -Force -Path $stage | Out-Null
    Write-AcquireLog $LogPath ("iOS AFC/house_arrest starting dest={0}" -f $stage)
    if ($ProgressFile) {
        try {
            $backupGb = [math]::Round($BackupBytes / 1GB, 2)
            (@{
                stage         = "acquire"
                item          = "afc_media"
                category      = "Collecting"
                detail        = ('iTunes backup finished ({0} GB). Now pulling shared photos and WhatsApp container - next step, not a new collection.' -f $backupGb)
                progress_mode = "bytes"
                run_name      = ""
                output_path   = $stage
                bytes_done    = [int64]$BackupBytes
                files_seen    = [int]$BackupFiles
                backup_bytes  = [int64]$BackupBytes
                backup_files  = [int]$BackupFiles
                progress_pct  = 72
                phase         = "afc_media"
                phase_progress_pct = $null
            } | ConvertTo-Json -Compress) | Set-Content -LiteralPath $ProgressFile -Encoding UTF8
        } catch {}
    }
    $errFile = Join-Path $OutDir "afc.err"
    $outFile = Join-Path $OutDir "afc.out"
    $prevPy = $env:PYTHONPATH
    $env:PYTHONPATH = Get-KitPythonPathEnv
    $proc = Start-Process -FilePath $py -ArgumentList @($scriptPath, "--udid", $Udid, "--dest", $stage) `
        -PassThru -NoNewWindow -RedirectStandardError $errFile -RedirectStandardOutput $outFile
    $env:PYTHONPATH = $prevPy
    $cancel = ""
    if ($ProgressFile) { $cancel = $ProgressFile + ".cancel" }
    while ($proc -and -not $proc.HasExited) {
        if ($cancel -and (Test-Path -LiteralPath $cancel)) {
            Write-AcquireLog $LogPath "Cancel file seen - stopping iPhone AFC pull."
            & taskkill.exe /PID $proc.Id /T /F 2>$null | Out-Null
            break
        }
        $stats = Get-DirFileStats -Dir $stage
        if ($ProgressFile) {
            try {
                $gb = [math]::Round(([int64]$stats.bytes) / 1GB, 2)
                $backupGb = [math]::Round($BackupBytes / 1GB, 2)
                $totalBytes = [int64]$BackupBytes + [int64]$stats.bytes
                $totalFiles = [int]$BackupFiles + [int]$stats.files
                (@{
                    stage         = "acquire"
                    item          = "afc_media"
                    category      = "Collecting"
                    detail        = ('Backup already saved ({0} GB). AFC/WhatsApp add-on now {1} GB, {2} files. Same collection - not a restart.' -f $backupGb, $gb, $stats.files)
                    bytes_done    = $totalBytes
                    files_seen    = $totalFiles
                    backup_bytes  = [int64]$BackupBytes
                    backup_files  = [int]$BackupFiles
                    afc_bytes     = [int64]$stats.bytes
                    afc_files     = [int]$stats.files
                    progress_mode = "bytes"
                    progress_pct  = 74
                    phase         = "afc_media"
                    phase_progress_pct = $null
                    output_path   = $stage
                } | ConvertTo-Json -Compress) | Set-Content -LiteralPath $ProgressFile -Encoding UTF8
            } catch {}
        }
        Start-Sleep -Seconds 4
    }
    if ($proc -and -not $proc.HasExited) {
        try { $proc.WaitForExit() } catch {}
    }
    $stats = Get-DirFileStats -Dir $stage
    $ok = ([int]$stats.files -gt 0)
    if ($ok) {
        $commit = Move-IosStageIntoCase -Stage $stage -OutDir $OutDir -LogPath $LogPath
        if (-not $commit.ok) {
            Write-AcquireLog $LogPath ("iOS AFC staging commit failed: {0}" -f $commit.error)
            return @{ ok = $false; method = "ios_afc_house_arrest"; files = [int]$stats.files; bytes = [int64]$stats.bytes; dest = $stage; error = $commit.error }
        }
    }
    $finalStats = Get-DirFileStats -Dir $OutDir
    Write-AcquireLog $LogPath ("iOS AFC/house_arrest finished and committed to case files={0} bytes={1} ok={2}" -f $stats.files, $stats.bytes, $ok)
    return @{ ok = $ok; method = "ios_afc_house_arrest"; files = [int]$stats.files; bytes = [int64]$stats.bytes; dest = $OutDir; total_case_files = [int]$finalStats.files; total_case_bytes = [int64]$finalStats.bytes }
}

function Invoke-IosReadableArtifacts {
    <#
    iOS Agent only. Unpacks hashed iTunes backup DBs (ChatStorage, SMS) into
    readable_artifacts. Android jobs must not call this.
    #>
    param(
        [string]$Original,
        [string]$Exports = "",
        [string]$LogPath = ""
    )
    $py = Find-IosKitPython
    $scriptPath = Join-Path (Get-RepoRoot) "scripts\ios_readable_cli.py"
    if (-not $py -or -not (Test-Path -LiteralPath $scriptPath)) {
        Write-AcquireLog $LogPath "ios_readable_cli.py missing - WhatsApp hashes will stay hashed."
        return @{ ok = $false; error = "ios_readable_cli_missing" }
    }
    Write-AcquireLog $LogPath ("Materialising iOS readable artefacts from {0}" -f $Original)
    $errFile = Join-Path $env:TEMP ("aetheris_ios_readable_" + [guid]::NewGuid().ToString("N") + ".err")
    $outFile = Join-Path $env:TEMP ("aetheris_ios_readable_" + [guid]::NewGuid().ToString("N") + ".out")
    $prevPy = $env:PYTHONPATH
    $env:PYTHONPATH = Get-KitPythonPathEnv
    $args = @($scriptPath, "--original", $Original)
    if ($Exports) { $args += @("--exports", $Exports) }
    try {
        $proc = Start-Process -FilePath $py -ArgumentList $args -Wait -PassThru -NoNewWindow `
            -RedirectStandardOutput $outFile -RedirectStandardError $errFile
    } catch {
        Write-AcquireLog $LogPath ("ios readable materialise failed: {0}" -f $_.Exception.Message)
    }
    $env:PYTHONPATH = $prevPy
    $raw = ""
    if (Test-Path -LiteralPath $outFile) { $raw = Get-Content -LiteralPath $outFile -Raw -ErrorAction SilentlyContinue }
    Remove-Item -LiteralPath $outFile, $errFile -Force -ErrorAction SilentlyContinue
    $readableNote = (($raw -replace '\s+', ' ').Trim())
    if ($readableNote.Length -gt 500) { $readableNote = $readableNote.Substring(0, 500) }
    Write-AcquireLog $LogPath ("iOS readable artefacts: {0}" -f $readableNote)
    return @{ ok = $true; detail = $raw }
}

function Invoke-AndroidReadableArtifacts {
    <#
    Android Agent only. Copies DCIM/Pictures, .trashed leftovers, and WhatsApp
    media into readable_artifacts. iOS jobs must not call this.
    #>
    param(
        [string]$Original,
        [string]$Exports = "",
        [string]$LogPath = ""
    )
    $py = Find-IosKitPython
    $scriptPath = Join-Path (Get-RepoRoot) "scripts\android_readable_cli.py"
    if (-not $py -or -not (Test-Path -LiteralPath $scriptPath)) {
        Write-AcquireLog $LogPath "android_readable_cli.py missing - trash/WhatsApp leftovers stay in the pull tree."
        return @{ ok = $false; error = "android_readable_cli_missing" }
    }
    Write-AcquireLog $LogPath ("Materialising Android readable artefacts from {0}" -f $Original)
    $errFile = Join-Path $env:TEMP ("aetheris_android_readable_" + [guid]::NewGuid().ToString("N") + ".err")
    $outFile = Join-Path $env:TEMP ("aetheris_android_readable_" + [guid]::NewGuid().ToString("N") + ".out")
    $prevPy = $env:PYTHONPATH
    $env:PYTHONPATH = Get-KitPythonPathEnv
    $cliArgs = @($scriptPath, "--original", $Original)
    if ($Exports) { $cliArgs += @("--exports", $Exports) }
    try {
        $proc = Start-Process -FilePath $py -ArgumentList $cliArgs -Wait -PassThru -NoNewWindow `
            -RedirectStandardOutput $outFile -RedirectStandardError $errFile
    } catch {
        Write-AcquireLog $LogPath ("android readable materialise failed: {0}" -f $_.Exception.Message)
    }
    $env:PYTHONPATH = $prevPy
    $raw = ""
    if (Test-Path -LiteralPath $outFile) { $raw = Get-Content -LiteralPath $outFile -Raw -ErrorAction SilentlyContinue }
    Remove-Item -LiteralPath $outFile, $errFile -Force -ErrorAction SilentlyContinue
    $androidNote = (($raw -replace '\s+', ' ').Trim())
    if ($androidNote.Length -gt 500) { $androidNote = $androidNote.Substring(0, 500) }
    Write-AcquireLog $LogPath ("Android readable artefacts: {0}" -f $androidNote)
    return @{ ok = $true; detail = $raw }
}

function New-MobileLogicalZip {
    param([string]$SourceDir, [string]$ZipPath, [string]$LogPath)
    if (Test-Path -LiteralPath $ZipPath) {
        Remove-Item -LiteralPath $ZipPath -Force -ErrorAction SilentlyContinue
    }
    Add-Type -AssemblyName System.IO.Compression.FileSystem
    try {
        [System.IO.Compression.ZipFile]::CreateFromDirectory($SourceDir, $ZipPath, [System.IO.Compression.CompressionLevel]::Optimal, $false)
        Write-AcquireLog $LogPath ("Created image package zip: {0}" -f $ZipPath)
        return $true
    }
    catch {
        Write-AcquireLog $LogPath ("Zip failed: {0}" -f $_.Exception.Message)
        return $false
    }
}

function Invoke-PythonOrchestratorAcquire {
    <#
    Prefer the UFED-aligned Python CollectionOrchestrator on the examiner host
    (docs/ADR-UFED-4PC-architecture-compliance.md). Falls back to legacy PS paths.
    #>
    param(
        [Parameter(Mandatory = $true)][string]$JobId,
        [string]$DeviceId = "",
        [string]$DeviceName = "",
        [string]$OsHint = "other",
        [string]$OutputRoot = ""
    )
    $repo = Get-RepoRoot
    $backend = Join-Path $repo "backend"
    $cliMod = "app.services.mobile_acquire.cli"
    $pyCandidates = @(
        (Join-Path $repo "tools\host-python\Scripts\python.exe"),
        (Join-Path $backend ".venv\Scripts\python.exe"),
        (Join-Path $repo ".venv\Scripts\python.exe"),
        "python",
        "py"
    )
    $python = $null
    foreach ($c in $pyCandidates) {
        if ($c -eq "python" -or $c -eq "py") {
            $cmd = Get-Command $c -ErrorAction SilentlyContinue
            if ($cmd) { $python = $cmd.Source; break }
        }
        elseif (Test-Path -LiteralPath $c) { $python = $c; break }
    }
    if (-not $python) { return $null }

    $argList = @(
        "-m", $cliMod,
        "--job-id", $JobId,
        "--device-id", $DeviceId,
        "--device-name", $DeviceName,
        "--os-hint", $OsHint
    )
    if ($OutputRoot) { $argList += @("--output-root", $OutputRoot) }
    $argList += "--network-isolated"

    try {
        Push-Location $backend
        $env:PYTHONPATH = $backend
        $pt = Join-Path (Get-RepoRoot) "tools\platform-tools"
        $lid = Join-Path (Get-RepoRoot) "tools\libimobiledevice"
        $env:PATH = "$pt;$lid;$env:LOCALAPPDATA\Android\Sdk\platform-tools;$env:PATH"
        $raw = & $python @argList 2>&1 | Out-String
        Pop-Location
        if (-not $raw) { return $null }
        # Last JSON object line (ignore any stray logs).
        $jsonLine = ($raw -split "`r?`n" | Where-Object { $_.Trim().StartsWith("{") } | Select-Object -Last 1)
        if (-not $jsonLine) { return $null }
        $obj = $jsonLine | ConvertFrom-Json
        if (-not $obj) { return $null }
        if (-not $obj.ok) {
            return @{
                ok             = $false
                error          = [string]($obj.error -or $obj.message -or "python orchestrator failed")
                engine         = "python_orchestrator"
                warnings       = @($obj.warnings)
            }
        }
        return @{
            ok              = $true
            engine          = "python_orchestrator"
            output_path     = [string]$obj.output_path
            backup_path     = [string]$obj.backup_path
            original_path   = [string]$obj.original_path
            working_path    = [string]$obj.working_path
            zip_name        = $null
            primary_method  = [string]$obj.primary_method
            methods         = @($obj.methods)
            files_copied    = [int]($obj.files_copied)
            message         = [string]$obj.message
            warnings        = @($obj.warnings)
            run_name        = [string]$obj.run_name
        }
    }
    catch {
        try { Pop-Location } catch {}
        return $null
    }
}

function Invoke-MobileAcquire {
    param(
        [Parameter(Mandatory = $true)][string]$JobId,
        [string]$DeviceId = "",
        [string]$DeviceName = "",
        [string]$OsHint = "other",
        [string]$InstanceId = "",
        [string]$OutputRoot = ""
    )

    $jobKey = ($JobId -replace '[^\w\-]', '_').Trim('_')
    if (-not $jobKey) { throw "job_id is required" }

    $root = if ($OutputRoot) { $OutputRoot.Trim().TrimEnd('\', '/') } else { Get-MobileAcquisitionRoot }
    $outDir = Join-Path $root $jobKey
    $logicalDir = Join-Path $outDir "logical"
    $logPath = Join-Path $outDir "acquire.log"
    $methods = New-Object System.Collections.Generic.List[string]
    $warnings = New-Object System.Collections.Generic.List[string]

    New-Item -ItemType Directory -Force -Path $logicalDir | Out-Null
    Write-AcquireLog $logPath ("Starting mobile acquisition for job {0}" -f $JobId)
    Write-AcquireLog $logPath ("Output directory: {0}" -f $outDir)
    Write-AcquireLog $logPath ("Device: name={0} os={1} id={2}" -f $DeviceName, $OsHint, $DeviceId)

    # Prefer UFED-aligned Python orchestrator (§7) when available on the host.
    $pyResult = Invoke-PythonOrchestratorAcquire `
        -JobId $JobId `
        -DeviceId $DeviceId `
        -DeviceName $DeviceName `
        -OsHint $OsHint `
        -OutputRoot $OutputRoot
    if ($null -ne $pyResult -and $pyResult.ok) {
        Write-AcquireLog $logPath ("Python orchestrator ok method={0} files={1} path={2}" -f `
            $pyResult.primary_method, $pyResult.files_copied, $pyResult.output_path)
        # Mirror package into job folder for existing register/ingest expectations.
        if ($pyResult.working_path -and (Test-Path -LiteralPath $pyResult.working_path)) {
            $marker = Join-Path $outDir "python_orchestrator_path.txt"
            Set-Content -LiteralPath $marker -Value $pyResult.working_path -Encoding UTF8
        }
        return $pyResult
    }
    if ($null -ne $pyResult -and -not $pyResult.ok -and $pyResult.error) {
        Write-AcquireLog $logPath ("Python orchestrator declined: {0} - trying legacy helper" -f $pyResult.error)
        $warnings.Add([string]$pyResult.error) | Out-Null
    }
    else {
        Write-AcquireLog $logPath "Python orchestrator unavailable - using legacy PowerShell ADB/iOS helpers"
    }

    $os = ([string]$OsHint).ToLowerInvariant()
    $filesCopied = 0
    $primaryMethod = "none"

    if ($os -eq "android") {
        $adbResult = Invoke-AndroidAdbAcquire -OutDir $outDir -LogPath $logPath
        if ($adbResult.ok) {
            $methods.Add([string]$adbResult.method) | Out-Null
            $primaryMethod = [string]$adbResult.method
            if ($adbResult.files_copied) { $filesCopied += [int]$adbResult.files_copied }
        }
        else {
            $warnings.Add([string]($adbResult.error)) | Out-Null
        }
    }

    $iosBackupPath = $null
    if ($os -eq "ios") {
        $udidHint = $DeviceId
        if ($udidHint -and $udidHint -notmatch '^[0-9A-Fa-f]{8}-[0-9A-Fa-f]{16}$|^[0-9A-Fa-f]{40}$') {
            $udidHint = ""
        }
        $iosResult = Invoke-IosToolAcquire -OutDir $outDir -LogPath $logPath -Udid $udidHint
        if ($iosResult.ok) {
            $methods.Add([string]$iosResult.method) | Out-Null
            $primaryMethod = [string]$iosResult.method
            $iosBackupPath = [string]$iosResult.backup_path
            if ($iosResult.files_copied) { $filesCopied += [int]$iosResult.files_copied }
            # Point logical package at the backup image (hard-link/junction style: copy markers + note path).
            if ($iosBackupPath -and (Test-Path -LiteralPath $iosBackupPath)) {
                $iosLogical = Join-Path $logicalDir "ios_backup"
                if (Test-Path -LiteralPath $iosLogical) {
                    Remove-Item -LiteralPath $iosLogical -Recurse -Force -ErrorAction SilentlyContinue
                }
                # Junction avoids duplicating multi-GB backups on disk.
                try {
                    $null = cmd.exe /c "mklink /J `"$iosLogical`" `"$iosBackupPath`"" 2>&1
                    if (-not (Test-Path -LiteralPath $iosLogical)) {
                        New-Item -ItemType Directory -Force -Path $iosLogical | Out-Null
                        Copy-Item -LiteralPath (Join-Path $iosBackupPath "*") -Destination $iosLogical -Recurse -Force -ErrorAction SilentlyContinue
                    }
                }
                catch {
                    New-Item -ItemType Directory -Force -Path $iosLogical | Out-Null
                    Copy-Item -LiteralPath (Join-Path $iosBackupPath "*") -Destination $iosLogical -Recurse -Force -ErrorAction SilentlyContinue
                }
                Write-AcquireLog $logPath ("iOS image linked into logical package: {0}" -f $iosBackupPath)
            }
        }
        else {
            $warnings.Add([string]($iosResult.error)) | Out-Null
            Write-AcquireLog $logPath ("iOS backup image failed: {0}" -f $iosResult.error)
        }
    }

    # MTP is photo/media only on iPhone - never a substitute for WhatsApp/SMS. Never use it for iOS imaging.
    $skipMtp = ($os -eq "ios")
    if (-not $skipMtp) {
        $mtp = Copy-MtpDeviceLogical `
            -DeviceName $DeviceName `
            -InstanceId $(if ($InstanceId) { $InstanceId } else { $DeviceId }) `
            -DestDir (Join-Path $logicalDir "mtp") `
            -LogPath $logPath `
            -OsHint $os
        if ($mtp.ok) {
            $methods.Add("mtp_logical") | Out-Null
            if ($primaryMethod -eq "none") { $primaryMethod = "mtp_logical" }
            $filesCopied += [int]$mtp.files_copied
            if ($os -eq "ios") {
                $warnings.Add("ios_mtp_is_not_a_forensic_image_use_idevicebackup2_or_UFED") | Out-Null
            }
        }
        else {
            $warnings.Add([string]($mtp.error)) | Out-Null
        }
    }
    else {
        Write-AcquireLog $logPath "Skipping MTP for iOS - use backup image / UFED import only (MTP cannot capture chats)."
    }

    # Recount files that may have landed asynchronously after CopyHere timeouts.
    $onDisk = @(Get-ChildItem -LiteralPath $logicalDir -Recurse -File -ErrorAction SilentlyContinue |
        Where-Object { $_.Name -ne "device_info.json" })
    if ($onDisk.Count -gt $filesCopied) {
        $filesCopied = $onDisk.Count
        if ($primaryMethod -eq "none") { $primaryMethod = "mtp_logical" }
        if (-not ($methods -contains "mtp_logical")) { $methods.Add("mtp_logical") | Out-Null }
        Write-AcquireLog $logPath ("Recounted {0} file(s) on disk after MTP settle." -f $filesCopied)
    }

    # Seed a minimal logical tree so zip/image package always exists for the pipeline.
    $deviceInfo = @{
        job_id         = $JobId
        device_name    = $DeviceName
        device_id      = $DeviceId
        instance_id    = $InstanceId
        os_hint        = $OsHint
        acquired_at    = (Get-Date).ToString("o")
        methods        = @($methods)
        files_copied   = $filesCopied
        primary_method = $primaryMethod
        warnings       = @($warnings)
        output_dir     = $outDir
    }
    $deviceInfoPath = Join-Path $logicalDir "device_info.json"
    ($deviceInfo | ConvertTo-Json -Depth 6) | Set-Content -LiteralPath $deviceInfoPath -Encoding UTF8

    $iosImageOk = ($primaryMethod -in @("idevicebackup2", "pymobiledevice3"))
    $acqMode = if ($iosImageOk) { "ios_backup_image" } else { "live_logical" }
    $manifest = @{
        schema             = "aetheris.mobile.acquisition.v1"
        job_id             = $JobId
        mobile_job_id      = $JobId
        acquisition_mode   = $acqMode
        provenance         = "host_helper_live"
        device_name        = $DeviceName
        os_hint            = $OsHint
        methods            = @($methods)
        primary_method     = $primaryMethod
        files_copied       = $filesCopied
        output_dir         = $outDir
        backup_path        = $iosBackupPath
        created_at         = (Get-Date).ToString("o")
        notes              = @(
            "iOS: idevicebackup2 full backup ~ UFED Advanced Logical (app data / chats when backup is readable).",
            "UFED Full File System / checkm8 / Premium extracts are import-only (.pas/.ufd folder).",
            "MTP photo export is NOT a phone image and will not contain WhatsApp/SMS databases.",
            "Package is registered into the normal mobile import + extracted-disk pipeline."
        )
        warnings           = @($warnings)
    }
    $manifestPath = Join-Path $outDir "acquisition_manifest.json"
    ($manifest | ConvertTo-Json -Depth 6) | Set-Content -LiteralPath $manifestPath -Encoding UTF8

    $zipName = "{0}_logical.zip" -f $jobKey
    $zipPath = Join-Path $outDir $zipName
    # For real iOS backups, zip can be multi-GB and slow - register the backup folder instead.
    $zipOk = $false
    $zipSize = [int64]0
    if ($iosImageOk -and $iosBackupPath) {
        Write-AcquireLog $logPath "Skipping large zip for iOS backup image - register backup folder directly."
        # Tiny marker zip so older clients still see a package file.
        $markerDir = Join-Path $outDir "_package_marker"
        New-Item -ItemType Directory -Force -Path $markerDir | Out-Null
        Copy-Item -LiteralPath $manifestPath -Destination (Join-Path $markerDir "acquisition_manifest.json") -Force
        "ios_backup_image=$iosBackupPath" | Set-Content -LiteralPath (Join-Path $markerDir "IMAGE_PATH.txt") -Encoding UTF8
        $zipOk = New-MobileLogicalZip -SourceDir $markerDir -ZipPath $zipPath -LogPath $logPath
    }
    else {
        $zipOk = New-MobileLogicalZip -SourceDir $logicalDir -ZipPath $zipPath -LogPath $logPath
    }
    if (-not $zipOk -or -not (Test-Path -LiteralPath $zipPath)) {
        throw "Failed to create logical image zip at $zipPath"
    }
    $zipSize = [int64](Get-Item -LiteralPath $zipPath).Length
    Write-AcquireLog $logPath ("Acquisition complete. zip_bytes={0} method={1}" -f $zipSize, $primaryMethod)

    # iOS must produce a real backup image - empty MTP zips are failures.
    if ($os -eq "ios") {
        $ok = $iosImageOk -and $iosBackupPath -and (Test-IosBackupComplete -Path $iosBackupPath)
    }
    else {
        $ok = ($filesCopied -gt 0) -or ($primaryMethod -in @("adb_backup", "adb_pull_sdcard")) -or ($zipSize -gt 64)
    }

    $registerPath = if ($ok -and $iosBackupPath) { $iosBackupPath } else { $outDir }
    $msg = if ($ok -and $os -eq "ios") {
        "iOS backup image created at $iosBackupPath - register this folder (UFED Advanced Logical equivalent)."
    }
    elseif ($ok) {
        "Logical extraction package created for job $JobId at $outDir"
    }
    elseif ($os -eq "ios") {
        "iOS image failed. Retry Advanced Logical; unlock the screen only if the log shows Error 208. Or import a UFED .pas/.ufd export / iTunes backup folder. See acquire.log."
    }
    else {
        "Acquisition folder created but little/no device content was copied. Check unlock/trust and acquire.log."
    }

    return @{
        ok               = [bool]$ok
        job_id           = $JobId
        mobile_job_id    = $JobId
        output_path      = $registerPath
        acquisition_dir  = $outDir
        backup_path      = $iosBackupPath
        zip_path         = $zipPath
        zip_name         = $zipName
        zip_bytes        = $zipSize
        files_copied     = $filesCopied
        primary_method   = $primaryMethod
        methods          = @($methods)
        warnings         = @($warnings)
        manifest_path    = $manifestPath
        log_path         = $logPath
        message          = $msg
        error            = if (-not $ok -and $warnings.Count) { [string]$warnings[0] } else { $null }
    }
}
