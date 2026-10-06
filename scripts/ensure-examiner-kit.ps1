# Bootstrap examiner-laptop USB / mobile tools into this repo (idempotent).
# Works on any Windows PC: no assumption of E:, a user site-packages, or iTunes PATH.
#
# Creates:
#   tools\host-python\     - isolated Python with pymobiledevice3 (iPhone usbmux)
#   tools\platform-tools\  - Google adb (Android)
# Optionally installs Apple Mobile Device Support via winget (iPhone USB driver).
#
# Called by startup.ps1 / ensure-host-drive-helper.ps1 / start-stack.ps1
param(
    [switch]$Force
)

$ErrorActionPreference = "Stop"
$root = Split-Path -Parent (Split-Path -Parent $MyInvocation.MyCommand.Path)
$tools = Join-Path $root "tools"
$venv = Join-Path $tools "host-python"
$venvPy = Join-Path $venv "Scripts\python.exe"
$adbDir = Join-Path $tools "platform-tools"
$adbExe = Join-Path $adbDir "adb.exe"
$reqFile = Join-Path $tools "host-python-requirements.txt"
$stamp = Join-Path $venv ".kit-ok"

function Write-Kit {
    param([string]$Message, [string]$Color = "Cyan")
    Write-Host "[examiner-kit] $Message" -ForegroundColor $Color
}

function Test-AppleMds {
    foreach ($p in @(
        "C:\Program Files\Common Files\Apple\Mobile Device Support",
        "C:\Program Files (x86)\Common Files\Apple\Mobile Device Support"
    )) {
        if (Test-Path -LiteralPath $p) { return $true }
    }
    $svc = Get-Service -ErrorAction SilentlyContinue | Where-Object {
        $_.Name -match 'AppleMobileDevice' -or $_.DisplayName -match 'Apple Mobile Device'
    } | Select-Object -First 1
    return [bool]$svc
}

function Test-PythonRuns {
    param([string]$Exe)
    if (-not $Exe -or -not (Test-Path -LiteralPath $Exe)) { return $false }
    if ($Exe -match '(?i)WindowsApps') { return $false }
    try {
        $prev = $ErrorActionPreference
        $ErrorActionPreference = "Continue"
        $null = & $Exe -c "print(1)" 2>$null
        $ErrorActionPreference = $prev
        return ($LASTEXITCODE -eq 0)
    } catch { return $false }
}

function Find-SystemPython {
    foreach ($p in @(
        "$env:LOCALAPPDATA\Programs\Python\Python312\python.exe",
        "$env:LOCALAPPDATA\Programs\Python\Python313\python.exe",
        "C:\Program Files\Python312\python.exe",
        "C:\Python312\python.exe",
        "C:\Python313\python.exe",
        "D:\install\anaconda3\python.exe",
        "$env:USERPROFILE\anaconda3\python.exe",
        "C:\ProgramData\anaconda3\python.exe",
        "$env:LOCALAPPDATA\Programs\Python\Python314\python.exe",
        "C:\Python314\python.exe"
    )) {
        if (Test-PythonRuns $p) { return $p }
    }
    foreach ($name in @("py", "python", "python3")) {
        $cmd = Get-Command $name -ErrorAction SilentlyContinue
        if (-not $cmd -or -not $cmd.Source) { continue }
        if ($cmd.Source -match '(?i)WindowsApps') { continue }
        if ($name -eq "py") {
            try {
                $ver = & $cmd.Source -3 -c "import sys; print(sys.executable)" 2>$null
                if ($ver -and (Test-PythonRuns $ver.Trim())) { return $ver.Trim() }
            } catch {}
            continue
        }
        if (Test-PythonRuns $cmd.Source) { return $cmd.Source }
    }
    return $null
}

New-Item -ItemType Directory -Force -Path $tools | Out-Null

if (-not (Test-Path -LiteralPath $reqFile)) {
    @(
        "pymobiledevice3>=4.0.0,<6",
        "typer>=0.12.0",
        "click>=8.1.0",
        "pywin32>=306"
    ) | Set-Content -Path $reqFile -Encoding ascii
}

function Test-HostPythonReady {
    if (-not (Test-Path -LiteralPath $venvPy)) { return $false }
    $cfg = Join-Path $venv "pyvenv.cfg"
    if (Test-Path -LiteralPath $cfg) {
        $homeLine = @(Get-Content -LiteralPath $cfg -TotalCount 8 -ErrorAction SilentlyContinue) |
            Where-Object { $_ -match '^\s*home\s*=' } | Select-Object -First 1
        if ($homeLine -match 'home\s*=\s*(.+)$') {
            $homePy = Join-Path $Matches[1].Trim() "python.exe"
            if (-not (Test-Path -LiteralPath $homePy)) { return $false }
        }
    }
    if (-not (Test-PythonRuns $venvPy)) { return $false }
    try {
        $prev = $ErrorActionPreference
        $ErrorActionPreference = "Continue"
        $null = & $venvPy -c "import pymobiledevice3, win32security" 2>$null
        $ErrorActionPreference = $prev
        return ($LASTEXITCODE -eq 0)
    } catch { return $false }
}

# --- Isolated Python for iOS usbmux (does not use a random user site-packages) ---
$needVenv = $Force -or -not (Test-HostPythonReady)
if ($needVenv) {
    $sysPy = Find-SystemPython
    if (-not $sysPy) {
        Write-Kit "No Python on this PC - installing Python 3.12 via winget..." "Yellow"
        $wg = Get-Command winget -ErrorAction SilentlyContinue
        if (-not $wg) {
            throw "Python is required for iPhone USB detection. Install Python 3.12+ and re-run."
        }
        & winget install -e --id Python.Python.3.12 --accept-package-agreements --accept-source-agreements
        $machinePath = [Environment]::GetEnvironmentVariable("Path", "Machine")
        $userPath = [Environment]::GetEnvironmentVariable("Path", "User")
        $env:Path = "$machinePath;$userPath"
        $sysPy = Find-SystemPython
        if (-not $sysPy) {
            foreach ($guess in @(
                "$env:LOCALAPPDATA\Programs\Python\Python312\python.exe",
                "$env:LOCALAPPDATA\Programs\Python\Python313\python.exe",
                "C:\Program Files\Python312\python.exe",
                "C:\Python312\python.exe"
            )) {
                if (Test-PythonRuns $guess) { $sysPy = $guess; break }
            }
        }
        if (-not $sysPy) {
            throw "Python install finished but python.exe was not found. Open a new terminal and re-run."
        }
    }
    Write-Kit "Creating tools\host-python from $sysPy"
    if (Test-Path -LiteralPath $venv) {
        Write-Kit "Removing broken or stale tools\host-python"
        Remove-Item -LiteralPath $venv -Recurse -Force -ErrorAction SilentlyContinue
    }
    & $sysPy -m venv $venv
    if (-not (Test-Path -LiteralPath $venvPy)) {
        throw "Failed to create $venvPy"
    }
    Write-Kit "Installing pymobiledevice3 + pywin32 into tools\host-python"
    & $venvPy -m pip install --upgrade pip --disable-pip-version-check
    & $venvPy -m pip install --disable-pip-version-check -r $reqFile
    if ($LASTEXITCODE -ne 0) {
        throw "pip install of host-python requirements failed"
    }
    $post = Join-Path $venv "Scripts\pywin32_postinstall.py"
    if (Test-Path -LiteralPath $post) {
        & $venvPy $post -install 2>$null
    }
    if (-not (Test-HostPythonReady)) {
        throw "host-python is missing pymobiledevice3 or pywin32 (win32security). Re-run with -Force."
    }
    Set-Content -Path $stamp -Value (Get-Date -Format o) -Encoding ascii
    Write-Kit "host-python ready" "Green"
} else {
    Write-Kit "host-python already present"
}

# --- Android platform-tools (adb) ---
function Find-ExistingAdbDir {
    $hits = @(
        (Join-Path $env:LOCALAPPDATA "Android\Sdk\platform-tools\adb.exe"),
        (Join-Path $env:LOCALAPPDATA "Microsoft\WinGet\Links\adb.exe"),
        "C:\Android\platform-tools\adb.exe"
    )
    foreach ($p in $hits) {
        if (Test-Path -LiteralPath $p) { return (Split-Path -Parent $p) }
    }
    $wingetRoot = Join-Path $env:LOCALAPPDATA "Microsoft\WinGet\Packages"
    if (Test-Path -LiteralPath $wingetRoot) {
        $found = Get-ChildItem -LiteralPath $wingetRoot -Filter "adb.exe" -Recurse -ErrorAction SilentlyContinue |
            Select-Object -First 1
        if ($found) { return $found.Directory.FullName }
    }
    $cmd = Get-Command adb.exe -ErrorAction SilentlyContinue
    if ($cmd -and $cmd.Source) { return (Split-Path -Parent $cmd.Source) }
    return $null
}

if ($Force -or -not (Test-Path -LiteralPath $adbExe)) {
    $existing = Find-ExistingAdbDir
    if ($existing -and (Test-Path -LiteralPath (Join-Path $existing "adb.exe"))) {
        Write-Kit "Copying adb from $existing"
        New-Item -ItemType Directory -Force -Path $adbDir | Out-Null
        Copy-Item -Path (Join-Path $existing "*") -Destination $adbDir -Force
    } else {
        Write-Kit "Downloading Google platform-tools (adb)..."
        $zip = Join-Path $env:TEMP "aetheris-platform-tools.zip"
        $url = "https://dl.google.com/android/repository/platform-tools-latest-windows.zip"
        Invoke-WebRequest -Uri $url -OutFile $zip -UseBasicParsing
        $extract = Join-Path $env:TEMP "aetheris-platform-tools-extract"
        if (Test-Path -LiteralPath $extract) {
            Remove-Item -LiteralPath $extract -Recurse -Force
        }
        Expand-Archive -LiteralPath $zip -DestinationPath $extract -Force
        $src = Join-Path $extract "platform-tools"
        if (-not (Test-Path -LiteralPath (Join-Path $src "adb.exe"))) {
            throw "platform-tools zip did not contain adb.exe"
        }
        if (Test-Path -LiteralPath $adbDir) {
            Remove-Item -LiteralPath $adbDir -Recurse -Force
        }
        Move-Item -LiteralPath $src -Destination $adbDir
        Remove-Item -LiteralPath $zip -Force -ErrorAction SilentlyContinue
    }
    if (-not (Test-Path -LiteralPath $adbExe)) {
        throw "adb.exe is still missing after examiner-kit setup"
    }
    Write-Kit "adb ready: $adbExe" "Green"
} else {
    Write-Kit "adb already present"
}

# --- Samsung USB driver (Galaxy ADB + MTP composite). Safe to skip. ---
$samsungInf = Get-ChildItem "C:\Windows\INF" -Filter "*ssud*" -ErrorAction SilentlyContinue |
    Select-Object -First 1
if (-not $samsungInf) {
    $wg = Get-Command winget -ErrorAction SilentlyContinue
    if ($wg) {
        Write-Kit "Installing Samsung USB driver for mobile phones (ADB)..." "Yellow"
        foreach ($pkg in @(
            "Samsung.USBDriverForMobilePhones",
            "Samsung.SamsungUSBDriverForMobilePhones"
        )) {
            try {
                & winget install -e --id $pkg --accept-package-agreements --accept-source-agreements
                if ($LASTEXITCODE -eq 0) { break }
            } catch {}
        }
    }
}

# --- Apple USB driver (iPhone). Safe to skip if winget/admin is missing. ---
if (-not (Test-AppleMds)) {
    $wg = Get-Command winget -ErrorAction SilentlyContinue
    if ($wg) {
        Write-Kit "Installing Apple Mobile Device Support (iPhone USB)..." "Yellow"
        try {
            & winget install -e --id Apple.AppleMobileDeviceSupport --accept-package-agreements --accept-source-agreements
        } catch {
            Write-Kit "Apple MDS install skipped: $($_.Exception.Message)" "Yellow"
        }
    }
    if (-not (Test-AppleMds)) {
        Write-Kit "Apple Mobile Device Support is not installed. iPhone USB needs: winget install Apple.AppleMobileDeviceSupport" "Yellow"
    } else {
        Write-Kit "Apple Mobile Device Support is installed" "Green"
        $svc = Get-Service -Name "Apple Mobile Device Service" -ErrorAction SilentlyContinue
        if ($svc -and $svc.Status -ne "Running") {
            try { Start-Service $svc.Name -ErrorAction SilentlyContinue } catch {}
        }
    }
} else {
    Write-Kit "Apple Mobile Device Support already present"
    $svc = Get-Service -ErrorAction SilentlyContinue | Where-Object {
        $_.Name -match 'AppleMobileDevice' -or $_.DisplayName -match 'Apple Mobile Device'
    } | Select-Object -First 1
    if ($svc -and $svc.Status -ne "Running") {
        try { Start-Service $svc.Name -ErrorAction SilentlyContinue } catch {}
    }
}

Write-Kit "Examiner kit ready (portable: tools\host-python + tools\platform-tools)" "Green"
Write-Host "  python: $venvPy"
Write-Host "  adb:    $adbExe"
