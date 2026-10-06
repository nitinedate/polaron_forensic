# Generate docker-compose.drives.generated.yml with read-only bind mounts for
# every drive letter that is currently present on this Windows workstation.
#
# The generated override contains ONLY the dynamic drive mounts. It does not
# repeat the application's normal volumes, so it cannot accidentally replace
# worker data mounts from docker-compose.yml.
#
# Usage:
#   powershell -File scripts/generate-drive-mounts.ps1
#   powershell -File scripts/generate-drive-mounts.ps1 -RequireDrive G
#   docker compose -f docker-compose.yml -f docker-compose.drives.generated.yml up -d --force-recreate api worker-disk worker-mobile worker-report

param(
    [string[]]$AlwaysInclude = @(),
    [string[]]$RequireDrive = @(),
    [string[]]$ExcludeDrive = @(),
    [string]$SourceMapPath = "",
    [ValidateSet("Windows", "Wsl")][string]$ExecutionMode = "Windows",
    [string]$OutputPath = "",
    [string[]]$ServiceNames = @(),
    [switch]$KeepRequiredForResolution
)

# `powershell -File` only binds the first token of an array. Allow a comma-separated
# string so start-stack and HostDrive remount always write worker mounts too.
if ($ServiceNames -and $ServiceNames.Count -eq 1 -and "$($ServiceNames[0])" -match ',') {
    $ServiceNames = @(
        $ServiceNames[0] -split ',' |
            ForEach-Object { $_.Trim() } |
            Where-Object { $_ }
    )
}

$ErrorActionPreference = "Stop"
$root = Split-Path -Parent (Split-Path -Parent $MyInvocation.MyCommand.Path)
if ($OutputPath) {
    $out = if ([System.IO.Path]::IsPathRooted($OutputPath)) { $OutputPath } else { Join-Path $root $OutputPath }
}
else {
    $out = Join-Path $root "docker-compose.drives.generated.yml"
}

function Normalize-DriveLetter {
    param([string]$Value)
    $text = ("$Value").Trim()
    if (-not $text) { return $null }
    if ($text -match '^([A-Za-z])(?::.*)?$') {
        return $Matches[1].ToUpper()
    }
    return $null
}


function Read-DriveSourceMap {
    param([string]$Path)
    $map = @{}
    if (-not $Path -or -not (Test-Path -LiteralPath $Path)) { return $map }
    try {
        $obj = Get-Content -LiteralPath $Path -Raw -ErrorAction Stop | ConvertFrom-Json
        $container = $obj
        if ($obj -and $obj.PSObject.Properties.Name -contains 'drives') {
            $container = $obj.drives
        }
        if ($container) {
            foreach ($prop in $container.PSObject.Properties) {
                $letter = Normalize-DriveLetter $prop.Name
                if (-not $letter) { continue }
                $value = $prop.Value
                $source = ""
                $mode = "legacy"
                if ($value -is [string]) {
                    $source = [string]$value
                }
                elseif ($value -and ($value.PSObject.Properties.Name -contains 'source')) {
                    $source = [string]$value.source
                    if ($value.PSObject.Properties.Name -contains 'mode' -and $value.mode) {
                        $mode = [string]$value.mode
                    }
                }
                if ($source) {
                    $map[$letter] = @{
                        source = $source
                        mode = $mode
                        wsl_distro = $(if ($value -and ($value.PSObject.Properties.Name -contains 'wsl_distro') -and $value.wsl_distro) { [string]$value.wsl_distro } else { '' })
                        wsl_mount = $(if ($value -and ($value.PSObject.Properties.Name -contains 'wsl_mount') -and $value.wsl_mount) { [string]$value.wsl_mount } else { '' })
                        mount_target = $(if ($value -and ($value.PSObject.Properties.Name -contains 'mount_target') -and $value.mount_target) { [string]$value.mount_target } else { '' })
                        source_scope = $(if ($value -and ($value.PSObject.Properties.Name -contains 'source_scope') -and $value.source_scope) { [string]$value.source_scope } else { '' })
                    }
                }
            }
        }
    }
    catch {
        Write-Warning ("Could not read drive source map {0}: {1}" -f $Path, $_.Exception.Message)
    }
    return $map
}

function Convert-ToYamlSingleQuoted {
    param([string]$Value)
    # YAML single-quoted scalars treat backslashes literally; double any single quote.
    return "'" + $Value.Replace("'", "''") + "'"
}

function Get-DaemonVolumeName {
    param([string]$Letter, [string]$Source)
    $sha = [System.Security.Cryptography.SHA256]::Create()
    try {
        $bytes = [System.Text.Encoding]::UTF8.GetBytes($Source)
        $hash = [BitConverter]::ToString($sha.ComputeHash($bytes)).Replace('-', '').ToLower()
    }
    finally {
        $sha.Dispose()
    }
    return ("aetheris_hostdrive_{0}_{1}" -f $Letter.ToLower(), $hash.Substring(0, 12))
}

function Test-DriveLetterPresent {
    param([string]$Letter)
    $L = Normalize-DriveLetter $Letter
    if (-not $L) { return $false }
    # USB / JMicron disks often have a letter on Get-Volume/Get-Partition while
    # Win32_LogicalDisk and sometimes Test-Path still miss them.
    try {
        $vol = Get-Volume -DriveLetter $L -ErrorAction SilentlyContinue
        if ($vol -and $vol.DriveType -ne 'CD-ROM') { return $true }
    }
    catch { }
    try {
        if (Get-Partition -DriveLetter $L -ErrorAction SilentlyContinue) { return $true }
    }
    catch { }
    try {
        if (-not (Test-Path -LiteralPath "${L}:\")) { return $false }
        $info = [System.IO.DriveInfo]::new("${L}:\")
        if ($info.DriveType -eq [System.IO.DriveType]::CDRom -and -not $info.IsReady) {
            return $false
        }
        return $true
    }
    catch {
        return [bool](Test-Path -LiteralPath "${L}:\")
    }
}

function Get-HostDriveLetters {
    $found = [System.Collections.Generic.HashSet[string]]::new([StringComparer]::OrdinalIgnoreCase)

    # Get-Volume sees USB external disks that Win32_LogicalDisk omits.
    try {
        Get-Volume -ErrorAction SilentlyContinue |
            Where-Object { $_.DriveLetter -and "$($_.DriveLetter)" -match '^[A-Z]$' } |
            ForEach-Object { [void]$found.Add("$($_.DriveLetter)".ToUpper()) }
    }
    catch { }
    try {
        Get-Partition -ErrorAction SilentlyContinue |
            Where-Object { $_.DriveLetter -and "$($_.DriveLetter)" -match '^[A-Z]$' } |
            ForEach-Object { [void]$found.Add("$($_.DriveLetter)".ToUpper()) }
    }
    catch { }
    try {
        Get-CimInstance -ClassName Win32_LogicalDisk -ErrorAction SilentlyContinue |
            Where-Object { $_.DeviceID -match '^[A-Z]:$' } |
            ForEach-Object { [void]$found.Add($_.DeviceID.Substring(0, 1).ToUpper()) }
    }
    catch { }
    try {
        Get-PSDrive -PSProvider FileSystem -ErrorAction SilentlyContinue |
            Where-Object { $_.Name -match '^[A-Z]$' } |
            ForEach-Object { [void]$found.Add($_.Name.ToUpper()) }
    }
    catch { }

    foreach ($code in ([int][char]'A')..([int][char]'Z')) {
        $letter = [string][char]$code
        if ($found.Contains($letter)) { continue }
        if (Test-DriveLetterPresent $letter) { [void]$found.Add($letter) }
    }

    return @($found | Where-Object { Test-DriveLetterPresent $_ } | Sort-Object)
}

function Test-DockerBindableWindowsDrive {
    param([string]$Letter)
    $L = Normalize-DriveLetter $Letter
    if (-not $L) { return $false }
    # C: is always required for the stack; Docker Desktop shares it.
    if ($L -eq 'C') { return $true }
    $docker = $null
    try { $docker = (Get-Command docker -ErrorAction SilentlyContinue).Source } catch { $docker = $null }
    if (-not $docker) {
        $guess = "C:\Program Files\Docker\Docker\resources\bin\docker.exe"
        if (Test-Path -LiteralPath $guess) { $docker = $guess }
    }
    if (-not $docker) { return $true }

    $images = @()
    try {
        $images = @(
            & $docker images --format "{{.Repository}}:{{.Tag}}" 2>$null |
                Where-Object { $_ -and $_ -ne "<none>:<none>" }
        )
    } catch { $images = @() }
    $image = @(
        $images |
            Where-Object { $_ -match '^(alpine|busybox|aetheris-forensic-api|aetheris-mobile-extract-api):' }
    )[0]
    if (-not $image) { $image = @($images | Select-Object -First 1)[0] }
    if (-not $image) { return $true }

    $src = "${L}:/"
    $prev = $ErrorActionPreference
    $ErrorActionPreference = "SilentlyContinue"
    try {
        & $docker run --rm --pull never -v "${src}:/probe:ro" --entrypoint /bin/true $image 1>$null 2>$null
        return ($LASTEXITCODE -eq 0)
    } catch {
        return $false
    } finally {
        $ErrorActionPreference = $prev
    }
}

$detected = @(Get-HostDriveLetters)
$requested = @(
    @($AlwaysInclude) + @($RequireDrive) |
        ForEach-Object { Normalize-DriveLetter $_ } |
        Where-Object { $_ }
)

$missingRequested = @($requested | Where-Object { -not (Test-DriveLetterPresent $_) } | Sort-Object -Unique)
if ($missingRequested.Count) {
    throw "Requested drive(s) are not available in Windows: $($missingRequested -join ', ')"
}

$excluded = @(
    @($ExcludeDrive) |
        ForEach-Object { Normalize-DriveLetter $_ } |
        Where-Object { $_ } |
        Sort-Object -Unique
)

$letters = @(
    $detected + $requested |
        Where-Object { $_ -and (Test-DriveLetterPresent $_) -and ($excluded -notcontains $_) } |
        Sort-Object -Unique
)

# Resolve the source map before the generic Windows-root bind test.  The
# refresh job may already have proven a safer source for a removable drive
# (Docker daemon path, WSL-integrated path, or an exact selected folder).  Do
# not throw that verified source away merely because a second probe of G:/ is
# empty/stale -- that is the failure this recovery path is designed to heal.
$sourceMap = Read-DriveSourceMap -Path $SourceMapPath

$kept = New-Object System.Collections.Generic.List[string]
$skippedDocker = New-Object System.Collections.Generic.List[string]
foreach ($letter in $letters) {
    $resolved = if ($sourceMap.ContainsKey($letter)) { $sourceMap[$letter] } else { $null }
    if ($resolved -and [string]$resolved.source) {
        $kept.Add($letter) | Out-Null
        continue
    }
    # First-pass refresh discovery must not discard the examiner-selected drive
    # just because the whole drive root is not bindable. The resolver that runs
    # immediately afterwards can prove an exact selected-folder or WSL source.
    if ($KeepRequiredForResolution -and ($requested -contains $letter)) {
        $kept.Add($letter) | Out-Null
        continue
    }
    if (Test-DockerBindableWindowsDrive $letter) {
        $kept.Add($letter) | Out-Null
    } else {
        $skippedDocker.Add($letter) | Out-Null
    }
}
$letters = @($kept)
if ($skippedDocker.Count) {
    Write-Warning ("Skipping unresolved drive(s) Docker Desktop cannot bind-mount: {0}. A drive with a verified HostDrive/WSL source is kept automatically." -f ($skippedDocker -join ', '))
}

if (-not $letters.Count) {
    throw "No ready Windows drive letters found."
}
$serviceNames = if ($ServiceNames -and $ServiceNames.Count) {
    $ServiceNames
} else {
    @('api', 'worker-disk', 'worker-parse', 'worker-mobile', 'worker-report', 'worker-agent')
}

# Resolve the effective source and mount strategy once per drive. WSL DrvFs
# bridge paths are paths on Docker's Linux host, not Windows paths. When
# Compose is launched from Windows, using those paths directly as service bind
# sources can be client-normalized incorrectly. For that case we create a
# pre-created external local volume whose opaque `device` option is interpreted
# by the Docker engine itself. Any verified Linux-daemon path (for example
# /mnt/wsl or /run/desktop) uses that strategy; Windows/UNC sources remain
# normal bind mounts.
$driveMounts = @{}
foreach ($letter in $letters) {
    $entry = if ($sourceMap.ContainsKey($letter)) { $sourceMap[$letter] } else { $null }
    $lower = $letter.ToLower()
    if ($ExecutionMode -eq 'Wsl') {
        # When Compose itself runs inside a Docker-Desktop-integrated WSL distro,
        # use Linux-visible paths. A drive resolved through the explicit DrvFs
        # bridge keeps that exact mount point; ordinary drives use /mnt/<letter>.
        $source = if ($entry -and $entry.mode -eq 'wsl-compose' -and $entry.wsl_mount) {
            [string]$entry.wsl_mount
        } else {
            "/mnt/$lower"
        }
        $mode = if ($entry -and $entry.mode) { [string]$entry.mode } else { 'wsl-compose' }
        $daemonPath = $false
    }
    else {
        $source = if ($entry) { [string]$entry.source } else { "${letter}:/" }
        $mode = if ($entry -and $entry.mode) { [string]$entry.mode } else { 'docker-direct' }
        $daemonPath = $source.StartsWith('/')
    }
    $target = if ($entry -and $entry.mount_target) { [string]$entry.mount_target } else { "/host/$lower" }
    $driveMounts[$letter] = @{
        source = $source
        mode = $mode
        target = $target
        source_scope = $(if ($entry -and $entry.source_scope) { [string]$entry.source_scope } else { 'drive' })
        daemon_path = $daemonPath
        volume_name = $(if ($daemonPath) { Get-DaemonVolumeName -Letter $letter -Source $source } else { "" })
    }
}

$lines = New-Object System.Collections.Generic.List[string]
$lines.Add('# Auto-generated dynamic Windows drive mounts. Do not edit by hand.') | Out-Null
$lines.Add('# Regenerate: powershell -File scripts/generate-drive-mounts.ps1') | Out-Null
$lines.Add($(if ($ExecutionMode -eq 'Wsl') { '# WSL execution mode: Linux-visible paths are mounted directly by Docker Desktop WSL Integration.' } else { '# Direct Windows paths use bind mounts. Verified daemon paths use pre-created external volumes.' })) | Out-Null
$lines.Add('') | Out-Null
$lines.Add('services:') | Out-Null

foreach ($service in $serviceNames) {
    $lines.Add("  ${service}:") | Out-Null
    $lines.Add('    volumes:') | Out-Null
    foreach ($letter in $letters) {
        $lower = $letter.ToLower()
        $m = $driveMounts[$letter]
        if ($m.daemon_path) {
            $lines.Add('      - type: volume') | Out-Null
            $lines.Add(("        source: {0}" -f $m.volume_name)) | Out-Null
            $lines.Add(('        target: {0}' -f (Convert-ToYamlSingleQuoted ([string]$m.target)))) | Out-Null
            $lines.Add('        read_only: true') | Out-Null
            $lines.Add('        volume:') | Out-Null
            $lines.Add('          nocopy: true') | Out-Null
        }
        else {
            $lines.Add('      - type: bind') | Out-Null
            $lines.Add(('        source: {0}' -f (Convert-ToYamlSingleQuoted ([string]$m.source)))) | Out-Null
            $lines.Add(('        target: {0}' -f (Convert-ToYamlSingleQuoted ([string]$m.target)))) | Out-Null
            $lines.Add('        read_only: true') | Out-Null
            $lines.Add('        bind:') | Out-Null
            $lines.Add('          create_host_path: false') | Out-Null
        }
    }
}

$daemonLetters = @($letters | Where-Object { $driveMounts[$_].daemon_path })
if ($daemonLetters.Count) {
    $lines.Add('') | Out-Null
    $lines.Add('volumes:') | Out-Null
    foreach ($letter in $daemonLetters) {
        $m = $driveMounts[$letter]
        $lines.Add(("  {0}:" -f $m.volume_name)) | Out-Null
        $lines.Add('    external: true') | Out-Null
        $lines.Add(("    name: {0}" -f $m.volume_name)) | Out-Null
    }
}

# UTF-8 without BOM avoids odd characters at the start of Compose YAML.
$text = ($lines -join "`n") + "`n"
[System.IO.File]::WriteAllText($out, $text, [System.Text.UTF8Encoding]::new($false))

Write-Host "Wrote $($letters.Count) drive mount(s) to $out"
# IMPORTANT: Invoke-DriveGenerator captures the success/output stream. Write-Host
# uses the host/information stream in Windows PowerShell 5.1, so the refresh job
# would otherwise see an empty result and incorrectly report "no drive letters".
Write-Output "Letters: $($letters -join ', ')"
