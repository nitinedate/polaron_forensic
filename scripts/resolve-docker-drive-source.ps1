# Resolve a Windows drive to a Docker-readable bind source.
#
# Why this exists:
# Docker Desktop can create a bind mount for a newly attached/removable Windows
# drive while exposing an empty/stale directory to Linux containers.  A plain
# "G:/ -> /host/g" Compose entry therefore is not sufficient evidence that the
# real disk is readable.
#
# Resolution order:
#   1. Test several Docker Desktop direct-source spellings against the exact
#      selected Windows path (or a root sentinel when no path was supplied).
#   2. If those fail, mount the Windows drive with WSL DrvFs under /mnt/wsl and
#      test Docker-accessible views of that bridge.
#
# The script never copies evidence bytes.  The final container mount remains
# read-only.  It writes a JSON result when -OutputFile is supplied.

param(
    [Parameter(Mandatory = $true)][string]$DriveLetter,
    [string]$RequiredPath = "",
    [string]$Root = "",
    [string]$ApiImage = "",
    [string]$OutputFile = "",
    [switch]$ForceWslBridge,
    [switch]$RemountOnly
)

$ErrorActionPreference = "Stop"

$env:DOCKER_CLI_HINTS = "false"

function Convert-NativeOutputToLines {
    # Normalises redirected native output (strings, and on Windows PowerShell
    # 5.1 ErrorRecord objects for stderr lines) into plain text lines.
    param($Output)
    $lines = @()
    foreach ($item in @($Output)) {
        if ($null -eq $item) { continue }
        $text = if ($item -is [System.Management.Automation.ErrorRecord]) {
            [string]$item.Exception.Message
        }
        else {
            [string]$item
        }
        # [char]27: the `e escape only exists in PowerShell 6+, not in 5.1.
        $esc = [char]27
        $text = ($text -replace "$esc\[[0-9;?]*[ -/]*[@-~]", '') -replace "`0", ''
        foreach ($piece in ($text -split "`r?`n")) {
            $trimmed = $piece.TrimEnd()
            if ($trimmed.Trim()) { $lines += $trimmed }
        }
    }
    return @($lines)
}

function Invoke-NativeCapture {
    # Run a native executable and capture stdout + stderr as text WITHOUT the
    # Windows PowerShell 5.1 behaviour where the first redirected stderr line
    # becomes a terminating error under $ErrorActionPreference = "Stop".
    # "docker info" (WARNING: lines) and "docker run" (image pull / python
    # tracebacks) both write to stderr in perfectly normal situations, and
    # previously made a healthy probe look like a failure.
    param(
        [Parameter(Mandatory = $true)][string]$FilePath,
        [string[]]$ArgumentList = @(),
        [string]$StdinText = ""
    )
    $ErrorActionPreference = "Continue"
    $global:LASTEXITCODE = 0
    $raw = @()
    $code = 0
    # A [string] parameter coerces $null to "", so use the bound-parameter set
    # to decide whether stdin should be fed to the process at all.
    $feedStdin = $PSBoundParameters.ContainsKey('StdinText')
    try {
        if ($feedStdin) {
            $raw = @($StdinText | & $FilePath @ArgumentList 2>&1)
        }
        else {
            $raw = @(& $FilePath @ArgumentList 2>&1)
        }
        $code = if ($null -ne $LASTEXITCODE) { [int]$LASTEXITCODE } else { 0 }
    }
    catch {
        $raw = @($raw) + @($_.Exception.Message)
        $code = -1
    }
    $global:LASTEXITCODE = $code
    $lines = @(Convert-NativeOutputToLines $raw)
    return @{
        ExitCode = $code
        Output   = $lines
        Text     = ($lines -join "`n")
    }
}

function Normalize-DriveLetter {
    param([string]$Value)
    $text = ("$Value").Trim()
    if ($text -match '^([A-Za-z])(?::.*)?$') {
        return $Matches[1].ToUpper()
    }
    return $null
}

function Convert-ToShSingleQuoted {
    param([string]$Value)
    # Used only for the fixed bridge path and drive spec, neither of which can
    # contain a single quote. Keep shell quoting intentionally simple here.
    if ($Value.Contains("'")) { throw "Unexpected single quote in bridge shell value" }
    return "'" + $Value + "'"
}

function Get-RequiredRelativePath {
    param([string]$Path, [string]$Letter)
    $text = ("$Path").Trim()
    if (-not $text) { return "" }
    if ($text -notmatch '^([A-Za-z]):[\\/]?(.*)$') {
        throw "RequiredPath must be an absolute Windows drive path. Received: $Path"
    }
    if ($Matches[1].ToUpper() -ne $Letter.ToUpper()) {
        throw "RequiredPath is on drive $($Matches[1].ToUpper()):, not ${Letter}:"
    }
    return (($Matches[2] -replace '\\', '/').Trim('/'))
}


function Get-ExactMountPlan {
    param([string]$Path, [string]$Letter)
    $text = ("$Path").Trim()
    if (-not $text) { return $null }
    $norm = $text -replace '/', '\\'
    if ($norm -notmatch '^([A-Za-z]):[\\/](.*)$') { return $null }
    if ($Matches[1].ToUpper() -ne $Letter.ToUpper()) { return $null }

    $item = $null
    try { $item = Get-Item -LiteralPath $norm -Force -ErrorAction Stop } catch { return $null }
    $source = if ($item.PSIsContainer) { [string]$item.FullName } else { [string]$item.DirectoryName }
    if (-not $source) { return $null }

    $sourceNorm = $source -replace '/', '\\'
    if ($sourceNorm -notmatch '^([A-Za-z]):[\\/]?(.*)$') { return $null }
    $sourceRel = (($Matches[2] -replace '\\', '/').Trim('/'))
    $lower = $Letter.ToLower()
    $target = if ($sourceRel) { "/host/$lower/$sourceRel" } else { "/host/$lower" }
    $probeRelative = if ($item.PSIsContainer) { "" } else { [string]$item.Name }

    return @{
        source = $source
        target = $target
        probe_relative = $probeRelative
        selected_is_file = (-not [bool]$item.PSIsContainer)
    }
}

function Get-RootSentinelRelativePath {
    param([string]$Letter)
    $rootPath = "${Letter}:\"
    try {
        $item = Get-ChildItem -LiteralPath $rootPath -Force -ErrorAction Stop |
            Select-Object -First 1
        if ($item) { return [string]$item.Name }
    }
    catch { }
    return ""
}

function Get-ApiImage {
    param([string]$Preferred)
    if ($Preferred) { return $Preferred }
    try {
        $psRun = Invoke-NativeCapture -FilePath 'docker' -ArgumentList @('ps', '--filter', 'label=com.docker.compose.service=api', '--format', '{{.ID}}')
        $apiId = if ($psRun.ExitCode -eq 0 -and $psRun.Output.Count) { ("$($psRun.Output[0])").Trim() } else { '' }
        if ($apiId) {
            $imgRun = Invoke-NativeCapture -FilePath 'docker' -ArgumentList @('inspect', '--format', '{{.Image}}', $apiId)
            $image = if ($imgRun.ExitCode -eq 0 -and $imgRun.Output.Count) { ("$($imgRun.Output[0])").Trim() } else { '' }
            if ($image) { return $image }
        }
    }
    catch { }
    # Project image name is stable in both base Compose files.  Do not pull it;
    # docker run will fail cleanly if it genuinely is absent.
    return "rag_new2-api"
}

function Test-WindowsLetterHasFiles {
    param([string]$Letter)
    $L = Normalize-DriveLetter $Letter
    if (-not $L) { return $false }
    try {
        return [bool](Get-ChildItem -LiteralPath "${L}:\" -Force -ErrorAction Stop | Select-Object -First 1)
    }
    catch {
        return $false
    }
}

function Test-DockerDesktopHostLetter {
    param([string]$Letter)
    $lower = ($Letter.ToLower())
    if ($lower -notmatch '^[a-z]$') { return $false }
    # An empty /mnt/host/g directory is NOT a mount. Docker Desktop and our own
    # mkdir leave stubs that make `ls` succeed while G: is invisible. Require a
    # real 9p/drvfs/virtiofs mount AND at least one directory entry.
    # Do not use $n / $(...) here: Windows PowerShell expands those before
    # wsl.exe sees the script, which made a live DrvFs mount look empty.
    $probe = Invoke-NativeCapture -FilePath 'wsl.exe' -ArgumentList @(
        '-d', 'docker-desktop', '--', 'sh', '-c',
        "grep -E ' /mnt/host/$lower ' /proc/mounts 2>/dev/null | grep -Eq '9p|drvfs|virtiofs|fuse' || exit 11; ls -A /mnt/host/$lower 2>/dev/null | grep -q ."
    )
    return ($probe.ExitCode -eq 0)
}

function Ensure-DockerDesktopHostLetter {
    # Newly attached Windows letters (G:, USB disks) are often missing from
    # Docker Desktop's /mnt/host until DrvFs is mounted there. Docker Desktop
    # also leaves a stale 9p share after a USB reconnect: ls says
    # "No such device" and a second mount on top of that 9p fails. Lazy-unmount
    # first, then bind DrvFs at every path the daemon uses.
    #
    # CRITICAL: `ls` on an empty stub returns 0. The remount is successful only
    # when /proc/mounts shows a real filesystem AND the directory has entries
    # (or Windows itself has no files to show).
    param([string]$Letter)
    $L = Normalize-DriveLetter $Letter
    if (-not $L) { return $false }
    if (Test-DockerDesktopHostLetter $L) { return $true }
    $lower = $L.ToLower()
    $hostPath = "/mnt/host/$lower"
    $tmpHost = "/tmp/docker-desktop-root/mnt/host/$lower"
    $tmpRun = "/tmp/docker-desktop-root/run/desktop/mnt/host/$lower"
    $driveSpec = "${L}:"
    # Hard-code every path. Shell variables ($t, $n) are eaten by Windows
    # PowerShell before wsl.exe runs, which unmounted G: and never remounted it.
    $shell = @"
set +e
umount -l $hostPath >/dev/null 2>&1
umount -l $tmpHost >/dev/null 2>&1
umount -l $tmpRun >/dev/null 2>&1
mkdir -p $hostPath $tmpHost $tmpRun
mount -t drvfs '$driveSpec' $hostPath -o ro,metadata || mount -t drvfs '$driveSpec' $hostPath -o ro || mount -t drvfs '$driveSpec' $hostPath
mount -t drvfs '$driveSpec' $tmpHost -o ro,metadata || mount -t drvfs '$driveSpec' $tmpHost -o ro || true
mount -t drvfs '$driveSpec' $tmpRun -o ro,metadata || mount -t drvfs '$driveSpec' $tmpRun -o ro || true
grep -E ' $hostPath ' /proc/mounts 2>/dev/null | grep -Eq '9p|drvfs|virtiofs|fuse' || exit 11
ls -A $hostPath 2>/dev/null | grep -q . || exit 12
exit 0
"@
    $mount = Invoke-NativeCapture -FilePath 'wsl.exe' -ArgumentList @(
        '-d', 'docker-desktop', '--', 'sh', '-c', $shell
    )
    if ($mount.ExitCode -ne 0) { return $false }
    return (Test-DockerDesktopHostLetter $L)
}

function Test-DockerSource {
    param(
        [Parameter(Mandatory = $true)][string]$Source,
        [Parameter(Mandatory = $true)][string]$Image,
        [string]$RelativePath = ""
    )
    $relBytes = [System.Text.Encoding]::UTF8.GetBytes(("$RelativePath"))
    $relB64 = [Convert]::ToBase64String($relBytes)
    # Empty base64 is omitted from docker argv on Windows, which crashed
    # sys.argv[1] and made a working G: bind look like a failed probe.
    if (-not $relB64) { $relB64 = 'Cg==' }
    $code = @'
import base64, pathlib, sys
root = pathlib.Path('/probe')
arg = sys.argv[1] if len(sys.argv) > 1 else ''
rel = base64.b64decode(arg).decode('utf-8', errors='strict').replace('\\', '/').strip('/') if arg else ''
if rel == '\n':
    rel = ''
target = root
if rel:
    for part in [p for p in rel.split('/') if p]:
        target = target / part
ok = root.is_dir() and target.exists()
if ok and target.is_dir():
    next(target.iterdir(), None)
raise SystemExit(0 if ok else 41)
'@

    $probeVolume = ""
    try {
        if ($Source.StartsWith('/')) {
            # The final Compose strategy for Docker-daemon/WSL paths is an
            # external local-driver volume. Probe through that exact mechanism,
            # not a Windows-side Compose bind, so a source is accepted only if
            # the real production mount path can read the selected evidence.
            $probeVolume = "aetheris_drive_probe_" + [guid]::NewGuid().ToString('N')
            $created = Invoke-NativeCapture -FilePath 'docker' -ArgumentList @(
                'volume', 'create', '--driver', 'local', '--opt', 'type=none', '--opt', 'o=bind',
                '--opt', ("device={0}" -f $Source), $probeVolume
            )
            if ($created.ExitCode -ne 0) {
                return @{
                    ok = $false
                    exit = $created.ExitCode
                    output = $created.Text
                }
            }
            $run = Invoke-NativeCapture -FilePath 'docker' -ArgumentList @(
                'run', '--rm', '--network', 'none', '--entrypoint', 'python',
                '--mount', "type=volume,source=$probeVolume,target=/probe,readonly",
                $Image, '-c', $code, $relB64
            )
        }
        else {
            $run = Invoke-NativeCapture -FilePath 'docker' -ArgumentList @(
                'run', '--rm', '--network', 'none', '--entrypoint', 'python',
                '--mount', "type=bind,source=$Source,target=/probe,readonly",
                $Image, '-c', $code, $relB64
            )
        }
        return @{
            ok     = ($run.ExitCode -eq 0)
            exit   = $run.ExitCode
            output = $run.Text
        }
    }
    catch {
        return @{
            ok     = $false
            exit   = -1
            output = $_.Exception.Message
        }
    }
    finally {
        if ($probeVolume) {
            Invoke-NativeCapture -FilePath 'docker' -ArgumentList @('volume', 'rm', '-f', $probeVolume) | Out-Null
        }
    }
}

function Get-WslDistros {
    # IMPORTANT (Windows PowerShell 5.1): avoid New-Object Generic List + @($list).
    # That combination can throw System.ArgumentException: "Argument types do not match".
    # Plain PowerShell arrays/hashtables are reliable in both Windows PowerShell 5.1
    # and PowerShell 7 and the distro list is tiny, so they are the safest choice.
    $ordered = @()
    $seen = @{}

    if ($env:AETHERIS_WSL_DISTRO) {
        $d = $env:AETHERIS_WSL_DISTRO.Trim()
        if ($d) {
            $key = $d.ToLowerInvariant()
            if (-not $seen.ContainsKey($key)) {
                $seen[$key] = $true
                $ordered += $d
            }
        }
    }

    try {
        $listRun = Invoke-NativeCapture -FilePath 'wsl.exe' -ArgumentList @('--list', '--quiet')
        foreach ($line in @($listRun.Output)) {
            $d = (("$line") -replace "`0", "").Trim()
            if (-not $d) { continue }
            if ($d -match '^docker-desktop-data$') { continue }
            # Prefer a normal distro; Docker Desktop itself is attempted last.
            if ($d -notmatch '^docker-desktop$') {
                $key = $d.ToLowerInvariant()
                if (-not $seen.ContainsKey($key)) {
                    $seen[$key] = $true
                    $ordered += $d
                }
            }
        }
        foreach ($line in @($listRun.Output)) {
            $d = (("$line") -replace "`0", "").Trim()
            if ($d -eq 'docker-desktop') {
                $key = $d.ToLowerInvariant()
                if (-not $seen.ContainsKey($key)) {
                    $seen[$key] = $true
                    $ordered += $d
                }
            }
        }
    }
    catch { }

    return $ordered
}

function Ensure-WslDrvFsBridge {
    param(
        [Parameter(Mandatory = $true)][string]$Distro,
        [Parameter(Mandatory = $true)][string]$Letter,
        [string]$RelativePath = ""
    )
    $lower = $Letter.ToLower()
    $mountPoint = "/mnt/aetheris-host-drives/$lower"
    $qMount = Convert-ToShSingleQuoted $mountPoint
    $qDrive = Convert-ToShSingleQuoted "${Letter}:"

    # Rebind the current Windows drive letter inside the selected WSL distro.
    # v4.4 intentionally does NOT use /mnt/wsl as a daemon-local handoff: Docker
    # Desktop isolates docker-desktop from user distros. Instead Docker Compose
    # is later executed from this same WSL-integrated distro, which is the
    # supported path for bind-mounting Linux/WSL files into Linux containers.
    $shell = @"
set -eu
mkdir -p $qMount
if grep -qs " $mountPoint " /proc/mounts 2>/dev/null; then
  umount -l $qMount >/dev/null 2>&1 || true
fi
bridge_mode=ro
if mount -t drvfs -o metadata,ro $qDrive $qMount >/dev/null 2>&1; then
  bridge_mode=ro
elif mount -t drvfs -o ro $qDrive $qMount >/dev/null 2>&1; then
  bridge_mode=ro
elif mount -t drvfs -o metadata $qDrive $qMount >/dev/null 2>&1; then
  bridge_mode=rw
else
  mount -t drvfs $qDrive $qMount >/dev/null 2>&1
  bridge_mode=rw
fi
test -d $qMount
printf '__AETHERIS_BRIDGE_MODE__=%s\n' "`$bridge_mode"
"@

    try {
        $shRun = Invoke-NativeCapture -FilePath 'wsl.exe' -ArgumentList @('-d', $Distro, '-u', 'root', '--', 'sh', '-lc', $shell)
        $outText = $shRun.Text
        $bridgeReadOnly = ($outText -match '__AETHERIS_BRIDGE_MODE__=ro')
        return @{
            ok          = ($shRun.ExitCode -eq 0)
            distro      = $Distro
            mount_point = $mountPoint
            read_only   = $bridgeReadOnly
            output      = $outText
        }
    }
    catch {
        return @{
            ok          = $false
            distro      = $Distro
            mount_point = $mountPoint
            read_only   = $false
            output      = $_.Exception.Message
        }
    }
}


function Test-WslDockerIntegration {
    param([Parameter(Mandatory = $true)][string]$Distro)
    try {
        $info = Invoke-NativeCapture -FilePath 'wsl.exe' -ArgumentList @('-d', $Distro, '--exec', 'docker', 'info', '--format', '{{.ServerVersion}}')
        if ($info.ExitCode -ne 0) {
            return @{
                ok = $false
                distro = $Distro
                detail = $info.Text
            }
        }
        $compose = Invoke-NativeCapture -FilePath 'wsl.exe' -ArgumentList @('-d', $Distro, '--exec', 'docker', 'compose', 'version')
        if ($compose.ExitCode -ne 0) {
            return @{
                ok = $false
                distro = $Distro
                detail = $compose.Text
            }
        }
        return @{
            ok = $true
            distro = $Distro
            detail = (($info.Text, $compose.Text) -join "`n")
        }
    }
    catch {
        return @{ ok = $false; distro = $Distro; detail = $_.Exception.Message }
    }
}

function Test-DockerSourceViaWsl {
    param(
        [Parameter(Mandatory = $true)][string]$Distro,
        [Parameter(Mandatory = $true)][string]$Source,
        [Parameter(Mandatory = $true)][string]$Image,
        [string]$RelativePath = ""
    )
    $relBytes = [System.Text.Encoding]::UTF8.GetBytes(("$RelativePath"))
    $relB64 = [Convert]::ToBase64String($relBytes)
    # Empty base64 is omitted from docker argv on Windows, which crashed
    # sys.argv[1] and made a working G: bind look like a failed probe.
    if (-not $relB64) { $relB64 = 'Cg==' }
    $code = @'
import base64, pathlib, sys
root = pathlib.Path('/probe')
arg = sys.argv[1] if len(sys.argv) > 1 else ''
rel = base64.b64decode(arg).decode('utf-8', errors='strict').replace('\\', '/').strip('/') if arg else ''
if rel == '\n':
    rel = ''
target = root
if rel:
    for part in [p for p in rel.split('/') if p]:
        target = target / part
ok = root.is_dir() and target.exists()
if ok and target.is_dir():
    next(target.iterdir(), None)
raise SystemExit(0 if ok else 41)
'@
    $mountSpec = "type=bind,source=$Source,target=/probe,readonly"
    try {
        $run = Invoke-NativeCapture -FilePath 'wsl.exe' -ArgumentList @(
            '-d', $Distro, '--exec', 'docker', 'run', '--rm', '--network', 'none', '--entrypoint', 'python',
            '--mount', $mountSpec, $Image, '-c', $code, $relB64
        )
        return @{
            ok = ($run.ExitCode -eq 0)
            exit = $run.ExitCode
            output = $run.Text
        }
    }
    catch {
        return @{ ok = $false; exit = -1; output = $_.Exception.Message }
    }
}

function Get-AttemptSummary {
    param([object[]]$Attempts)
    $parts = @()
    foreach ($a in @($Attempts)) {
        if ($a.ok) { continue }
        $label = "mode=$($a.mode) source=$($a.source)"
        if ($a.distro) { $label += " distro=$($a.distro)" }
        $detail = ("$($a.detail)").Trim()
        if ($detail.Length -gt 500) { $detail = $detail.Substring(0, 500) }
        if ($detail) { $label += " detail=$detail" }
        $parts += $label
    }
    if ($parts.Count -gt 6) { $parts = @($parts | Select-Object -Last 6) }
    return ($parts -join ' | ')
}

function Write-Result {
    param([hashtable]$Result)
    $json = $Result | ConvertTo-Json -Depth 8 -Compress
    if ($OutputFile) {
        $parent = Split-Path -Parent $OutputFile
        if ($parent -and -not (Test-Path -LiteralPath $parent)) {
            New-Item -ItemType Directory -Force -Path $parent | Out-Null
        }
        [System.IO.File]::WriteAllText($OutputFile, $json, [System.Text.UTF8Encoding]::new($false))
    }
    Write-Output $json
}

$letter = Normalize-DriveLetter $DriveLetter
if (-not $letter) {
    Write-Result @{
        ok = $false; drive = $DriveLetter; error = "Invalid drive letter: $DriveLetter"; mode = "none"; source = ""
    }
    exit 2
}

$windowsRoot = "${letter}:\"
if (-not (Test-Path -LiteralPath $windowsRoot)) {
    Write-Result @{
        ok = $false; drive = $letter; error = "Windows cannot see drive ${letter}:"; mode = "none"; source = ""
    }
    exit 3
}

$normalizedRequired = ("$RequiredPath").Trim()
if ($normalizedRequired) {
    $normalizedRequired = $normalizedRequired -replace '/', '\\'
    if (-not (Test-Path -LiteralPath $normalizedRequired)) {
        Write-Result @{
            ok = $false; drive = $letter; error = "Windows cannot see the selected path: $normalizedRequired"; mode = "none"; source = ""
        }
        exit 4
    }
}

try {
    $relative = Get-RequiredRelativePath -Path $normalizedRequired -Letter $letter
}
catch {
    Write-Result @{
        ok = $false; drive = $letter; error = $_.Exception.Message; mode = "none"; source = ""
    }
    exit 5
}
if (-not $normalizedRequired -or -not $relative) {
    $relative = Get-RootSentinelRelativePath -Letter $letter
}

$image = Get-ApiImage -Preferred $ApiImage
$lower = $letter.ToLower()
$attempts = @()

# Prefer a narrow, read-only bind of the exact selected folder before trying to
# share the entire removable drive root. Docker Desktop can reject or expose an
# empty G:/ root while still accepting G:\Case\Evidence directly. For a
# selected E01 file we bind its parent folder so sibling E02/E03 segments remain
# available without copying evidence bytes.
if (-not $ForceWslBridge -and $normalizedRequired) {
    $exactPlan = Get-ExactMountPlan -Path $normalizedRequired -Letter $letter
    if ($exactPlan) {
        $exactProbe = Test-DockerSource -Source ([string]$exactPlan.source) -Image $image -RelativePath ([string]$exactPlan.probe_relative)
        $attempts += [pscustomobject]@{
            source = [string]$exactPlan.source
            mode = "docker-exact-path"
            target = [string]$exactPlan.target
            ok = [bool]$exactProbe.ok
            detail = $exactProbe.output
        }
        if ($exactProbe.ok) {
            Write-Result @{
                ok             = $true
                drive          = $letter
                source         = [string]$exactPlan.source
                mode           = "docker-exact-path"
                mount_target   = [string]$exactPlan.target
                source_scope   = "selected-folder"
                required_path  = $normalizedRequired
                probe_relative = [string]$exactPlan.probe_relative
                api_image      = $image
                attempts       = $attempts
                message        = "Docker can read the selected ${letter}: evidence folder directly; mounting only that folder read-only."
            }
            exit 0
        }
    }
}

if ($RemountOnly) {
    $ok = Ensure-DockerDesktopHostLetter -Letter $letter
    Write-Result @{
        ok     = [bool]$ok
        drive  = $letter
        source = "/mnt/host/$lower"
        mode   = "docker-desktop-host-remount"
        error  = $(if ($ok) { $null } else { "Could not attach ${letter}: under Docker Desktop /mnt/host/$lower" })
    }
    exit $(if ($ok) { 0 } else { 31 })
}

$desktopHostReady = Ensure-DockerDesktopHostLetter -Letter $letter
$attempts += [pscustomobject]@{
    source = "/mnt/host/$lower"
    mode = "docker-desktop-host"
    ok = [bool]$desktopHostReady
    detail = $(if ($desktopHostReady) { "Drive is visible in Docker Desktop at /mnt/host/$lower" } else { "Could not attach ${letter}: under Docker Desktop /mnt/host/$lower" })
}

if (-not $ForceWslBridge) {
    # Test exact bytes/path, not merely whether Docker created /probe. An empty
    # stale mount is the failure mode this resolver is designed to catch.
    # Prefer the remounted daemon path first: Windows G:\ binds stay empty
    # until DrvFs is attached at /mnt/host/g.
    $directSources = @(
        "/mnt/host/$lower",
        "${letter}:/",
        "${letter}:\",
        "/run/desktop/mnt/host/$lower",
        "/host_mnt/$lower",
        "/$lower"
    ) | Select-Object -Unique

    foreach ($source in $directSources) {
        $probe = Test-DockerSource -Source $source -Image $image -RelativePath $relative
        $attempts += [pscustomobject]@{ source = $source; mode = "direct"; ok = [bool]$probe.ok; detail = $probe.output }
        if ($probe.ok) {
            Write-Result @{
                ok             = $true
                drive          = $letter
                source         = $source
                mode           = "docker-direct"
                mount_target   = "/host/$lower"
                source_scope   = "drive"
                required_path  = $(if ($normalizedRequired) { $normalizedRequired } else { $null })
                probe_relative = $relative
                api_image      = $image
                attempts       = $attempts
                message        = "Docker can read ${letter}: directly."
            }
            exit 0
        }
    }
}

# Docker Desktop isolates its internal docker-desktop distribution from normal
# user distributions. A bind source mounted in Ubuntu is therefore not safely
# usable as a daemon-local path from the Windows docker.exe client. The reliable
# fallback is to use a WSL2 distribution with Docker Desktop WSL Integration
# enabled and run the Docker bind probe from that distribution. Docker Desktop
# then creates its supported docker-desktop-bind-mounts bridge for that distro.
$distros = @(Get-WslDistros)
if (-not $distros.Count) {
    Write-Result @{
        ok            = $false
        drive         = $letter
        source        = ""
        mode          = "none"
        required_path = $(if ($normalizedRequired) { $normalizedRequired } else { $null })
        attempts      = $attempts
        error         = "Docker cannot read ${letter}: directly and no WSL2 user distribution is available. Install/enable a WSL2 distribution, enable Docker Desktop > Settings > Resources > WSL Integration for it, then retry."
    }
    exit 20
}

$integrationAvailable = $false
foreach ($distro in $distros) {
    if ($distro -match '^docker-desktop(?:-data)?$') { continue }

    $integration = Test-WslDockerIntegration -Distro $distro
    $attempts += [pscustomobject]@{
        source = "docker-cli"
        mode = "wsl-integration"
        distro = $distro
        ok = [bool]$integration.ok
        detail = $integration.detail
    }
    if (-not $integration.ok) { continue }
    $integrationAvailable = $true

    # First try WSL's normal automatic Windows-drive mount. This avoids any
    # remount and is sufficient on most machines, even when Windows docker.exe
    # exposes the same external drive as an empty directory.
    $autoMount = "/mnt/$lower"
    $autoProbe = Test-DockerSourceViaWsl -Distro $distro -Source $autoMount -Image $image -RelativePath $relative
    $attempts += [pscustomobject]@{
        source = $autoMount
        mode = "wsl-compose-auto"
        distro = $distro
        ok = [bool]$autoProbe.ok
        detail = $autoProbe.output
    }
    if ($autoProbe.ok) {
        Write-Result @{
            ok             = $true
            drive          = $letter
            source         = $autoMount
            mode           = "wsl-compose"
            mount_target   = "/host/$lower"
            source_scope   = "drive"
            wsl_distro     = $distro
            wsl_mount      = $autoMount
            wsl_bridge_read_only = $false
            required_path  = $(if ($normalizedRequired) { $normalizedRequired } else { $null })
            probe_relative = $relative
            api_image      = $image
            attempts       = $attempts
            message        = "Docker direct sharing was stale; ${letter}: is readable through Docker Desktop WSL Integration using $distro."
        }
        exit 0
    }

    # If /mnt/<letter> is absent/stale, explicitly bind the Windows drive into
    # this WSL distro with DrvFs and probe Docker from the SAME distro. This is
    # intentionally different from the old daemon-local-volume workaround.
    $bridge = Ensure-WslDrvFsBridge -Distro $distro -Letter $letter -RelativePath $relative
    $attempts += [pscustomobject]@{
        source = $bridge.mount_point
        mode = "wsl-provision"
        distro = $distro
        ok = [bool]$bridge.ok
        bridge_read_only = [bool]$bridge.read_only
        detail = $bridge.output
    }
    if (-not $bridge.ok) { continue }

    $mountPoint = [string]$bridge.mount_point
    $bridgeProbe = Test-DockerSourceViaWsl -Distro $distro -Source $mountPoint -Image $image -RelativePath $relative
    $attempts += [pscustomobject]@{
        source = $mountPoint
        mode = "wsl-compose-drvfs"
        distro = $distro
        ok = [bool]$bridgeProbe.ok
        detail = $bridgeProbe.output
    }
    if ($bridgeProbe.ok) {
        Write-Result @{
            ok             = $true
            drive          = $letter
            source         = $mountPoint
            mode           = "wsl-compose"
            mount_target   = "/host/$lower"
            source_scope   = "drive"
            wsl_distro     = $distro
            wsl_mount      = $mountPoint
            wsl_bridge_read_only = [bool]$bridge.read_only
            required_path  = $(if ($normalizedRequired) { $normalizedRequired } else { $null })
            probe_relative = $relative
            api_image      = $image
            attempts       = $attempts
            message        = $(if ($bridge.read_only) {
                "Docker direct sharing was stale; ${letter}: is available through a read-only WSL DrvFs mount and Docker Desktop WSL Integration."
            } else {
                "Docker direct sharing was stale; ${letter}: is available through WSL DrvFs and Docker Desktop WSL Integration. Aetheris container mounts remain read-only."
            })
        }
        exit 0
    }
}

$summary = Get-AttemptSummary -Attempts $attempts
if (-not $desktopHostReady) {
    $errorText = "Windows can read '$normalizedRequired', but Docker Desktop left an empty stub for ${letter}:. HostDrive could not attach DrvFs at /mnt/host/$lower. Retry Select disk folder. If this persists, restart Docker Desktop and remount the drive."
}
elseif (-not $integrationAvailable) {
    $errorText = "Windows can read '$normalizedRequired' and Docker Desktop /mnt/host/$lower was remounted, but the container probe still failed. Retry Select disk folder so HostDrive can recreate the forensic API with the verified mount."
}
else {
    $errorText = $(if ($normalizedRequired) {
        "Windows and WSL can see '$normalizedRequired', but the Docker Desktop WSL-integrated bind probe still could not expose it to Linux containers."
    } else {
        "Windows can read ${letter}:, but the Docker Desktop WSL-integrated bind probe could not expose the drive to Linux containers."
    })
}
if ($summary) { $errorText += " Attempts: $summary" }
Write-Result @{
    ok            = $false
    drive         = $letter
    source        = ""
    mode          = "none"
    required_path = $(if ($normalizedRequired) { $normalizedRequired } else { $null })
    attempts      = $attempts
    error         = $errorText
}
exit 30
