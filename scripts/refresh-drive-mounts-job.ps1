# One-shot dynamic drive refresh job.
#
# Responsibilities:
#   * Detect the actual Compose base used by the running API (http/https).
#   * Detect every currently present Windows drive letter (A:..Z:).
#   * Resolve each drive to a Docker-readable source.  Direct Docker Desktop
#     sharing is tested against real content; stale/empty removable-drive mounts
#     automatically fall back to a WSL2 DrvFs bridge without copying evidence.
#   * Generate a Compose override with read-only /host/<letter> mounts.
#   * Recreate only the forensic services and verify the exact selected path.
#
# Invoked asynchronously by host-drive-helper.ps1.

param(
    [Parameter(Mandatory = $true)][string]$Root,
    [Parameter(Mandatory = $true)][string]$StatusFile,
    [string]$RequiredPath = ""
)

$ErrorActionPreference = "Stop"

# Version marker. host-drive-helper.ps1 reports it on /health as
# job_script_version and ensure-host-drive-helper.ps1 restarts a helper whose
# loaded job script is older than the one on disk.
# AETHERIS_JOB_VERSION: 4.14
$script:JobVersion = "4.14"

# Docker Compose writes progress ("Container x Recreate", "Waiting", ...) to
# stderr. Keep that output plain so it can be logged and filtered reliably.
$env:COMPOSE_ANSI = "never"
$env:DOCKER_CLI_HINTS = "false"

function Convert-NativeOutputToLines {
    # Normalises what a redirected native command returns (strings and, on
    # Windows PowerShell 5.1, ErrorRecord objects for stderr lines) into plain
    # trimmed text lines without ANSI escapes or carriage returns.
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
        $text = $text -replace "$esc\[[0-9;?]*[ -/]*[@-~]", ''
        foreach ($piece in ($text -split "`r?`n")) {
            $trimmed = $piece.TrimEnd()
            if ($trimmed.Trim()) { $lines += $trimmed }
        }
    }
    return @($lines)
}

function Invoke-NativeCapture {
    # Run a native executable and capture stdout + stderr as text.
    #
    # IMPORTANT (Windows PowerShell 5.1): when stderr is redirected (2>&1 or
    # 2>$null) while $ErrorActionPreference is "Stop", the FIRST stderr line is
    # turned into a terminating NativeCommandError. Docker Compose prints its
    # progress lines on stderr, so a perfectly healthy
    # "docker compose up -d --force-recreate" aborted this job with
    # "Container rag_new2-worker-disk-1 Recreate" as the error message.
    # This wrapper relaxes the preference for the duration of the call only.
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
        # e.g. executable not found. Surface it as a failed exit, never a throw.
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

$generateScript = Join-Path $Root "scripts\generate-drive-mounts.ps1"
$resolveSourceScript = Join-Path $Root "scripts\resolve-docker-drive-source.ps1"
$composeDrives = Join-Path $Root "docker-compose.drives.generated.yml"
$composeDrivesWsl = Join-Path $Root "docker-compose.drives.wsl.generated.yml"
$stateDir = Join-Path $env:LOCALAPPDATA "Aetheris"
$sourceStateFile = Join-Path $stateDir "docker-drive-sources.json"
$detectCompose = Join-Path $stateDir "docker-compose.drives.detect.yml"
New-Item -ItemType Directory -Force -Path $stateDir | Out-Null

$script:ComposeBase = Join-Path $Root "docker-compose.yml"
$script:ComposeFiles = @($script:ComposeBase)
$script:ComposeProject = ""
# Project directory used when the running stack was started (the label
# com.docker.compose.project.working_dir). The split stacks in services/* are
# started with "--project-directory ." from the repo root, and their include:
# entries are root-relative. Without this, Compose defaults the project dir to
# the folder of the first -f file and "include: docker-compose.gvm.yml" fails.
$script:ComposeWorkingDir = $Root
$script:ComposeConfigLabel = ""
$script:ComposeDrivesFile = $composeDrives
$script:RemountServices = @('api', 'worker-disk', 'worker-parse', 'worker-mobile', 'worker-report')

function Test-IsDriveOverrideFile {
    param([string]$Path)
    $name = Split-Path -Leaf $Path
    return $name -match '^docker-compose\.drives(\.|$)'
}

function Set-RemountTarget {
    param([string]$Project)
    $name = ("$Project").Trim()
    if ($name -eq 'aetheris-forensic') {
        $script:ComposeDrivesFile = Join-Path $Root "docker-compose.drives.forensic.yml"
        $script:RemountServices = @('api', 'worker-disk', 'worker-parse', 'worker-report', 'worker-agent')
        return
    }
    if ($name -eq 'aetheris-mobile-android' -or $name -eq 'aetheris-mobile-ios') {
        $leaf = if ($name -eq 'aetheris-mobile-android') { 'mobile-android' } else { 'mobile-ios' }
        $script:ComposeDrivesFile = Join-Path $Root "docker-compose.drives.$leaf.yml"
        $script:RemountServices = @('api', 'worker-build', 'worker-parse')
        return
    }
    if ($name -eq 'aetheris-mobile-extract') {
        $script:ComposeDrivesFile = Join-Path $Root "docker-compose.drives.mobile.yml"
        $script:RemountServices = @('api', 'worker-mobile')
        return
    }
    $script:ComposeDrivesFile = $composeDrives
    $script:RemountServices = @('api', 'worker-disk', 'worker-parse', 'worker-mobile', 'worker-report')
}

function Test-ComposeProgressLine {
    # True for Docker Compose progress/status lines that carry no diagnostic
    # value ("Container api-1 Recreate", "Container api-1 Healthy", ...).
    param([string]$Line)
    $verbs = 'Recreate|Recreated|Recreating|Starting|Started|Running|Stopping|Stopped|Creating|Created|Removing|Removed|Waiting|Healthy|Pulling|Pulled|Building|Built'
    return ($Line -match "^\[?\+?\]?\s*(Container|Image|Volume|Network|Service)\s+\S+\s+($verbs)(\s+[\d.]+s)?$") -or
           ($Line -match '^\[\+\]\s+(Running|Creating|Building|Pulling)\s+\d+/\d+') -or
           ($Line -match '^(Recreate|Recreated|Starting|Started|Running|Healthy|Waiting|Creating|Created)(\s+[\d.]+s)?$')
}

function Get-ComposeFailureDetail {
    param($Output, [int]$ExitCode = -1)
    $lines = @(
        @(Convert-NativeOutputToLines $Output) | ForEach-Object { ("$_").Trim() } | Where-Object { $_ }
    )
    $prefix = if ($ExitCode -ge 0) { "docker compose up failed (exit $ExitCode)" } else { "docker compose up failed" }
    $errors = @(
        $lines | Where-Object {
            (-not (Test-ComposeProgressLine $_)) -and
            ($_ -match '(?i)error|failed|conflict|already in use|does not exist|invalid mount|Bind for|denied|not found|no such|cannot|unable')
        }
    )
    if ($errors.Count) {
        return "${prefix}: " + ($errors -join ' ')
    }
    $useful = @($lines | Where-Object { -not (Test-ComposeProgressLine $_) })
    if ($useful.Count) {
        return "${prefix}: " + ($useful -join ' ')
    }
    if ($lines.Count) {
        return "${prefix}. Last output: " + ($lines[-1])
    }
    return "${prefix} with no output."
}

function Get-ProjectPreference {
    param(
        [string]$Project,
        [string]$WorkingDir,
        [string]$RootFull
    )
    $name = ("$Project").Trim()
    $work = ("$WorkingDir").Trim().TrimEnd('\')
    $rootMatch = $false
    if ($work -and $RootFull) {
        $rootMatch = $work.Equals($RootFull, [StringComparison]::OrdinalIgnoreCase) -or
            $work.StartsWith($RootFull + '\', [StringComparison]::OrdinalIgnoreCase) -or
            $RootFull.StartsWith($work + '\', [StringComparison]::OrdinalIgnoreCase)
    }
    if ($name -eq 'aetheris-forensic') { return $(if ($rootMatch) { 0 } else { 2 }) }
    if ($name -eq 'aetheris-mobile-extract') { return $(if ($rootMatch) { 1 } else { 3 }) }
    if ($name -eq 'rag_new2') { return 80 }
    if ($rootMatch) { return 10 }
    return 50
}

function Write-Status([hashtable]$State) {
    $dir = Split-Path -Parent $StatusFile
    if ($dir -and -not (Test-Path -LiteralPath $dir)) {
        New-Item -ItemType Directory -Path $dir -Force | Out-Null
    }
    $State['job_version'] = $script:JobVersion
    $State['job_script'] = $PSCommandPath
    $State['job_root'] = $Root
    if ($RequiredPath -and -not $State.ContainsKey('required_path')) {
        $State.required_path = $RequiredPath
    }
    if (-not $State.ContainsKey('compose_base')) {
        $State.compose_base = (@($script:ComposeFiles) | ForEach-Object { Split-Path -Leaf $_ }) -join ','
    }
    ($State | ConvertTo-Json -Depth 10 -Compress) |
        Set-Content -Path $StatusFile -Encoding UTF8
}

function Get-RequiredDriveLetter {
    param([string]$Path)
    $text = ("$Path").Trim()
    if ($text -match '^([A-Za-z]):[\\/]') {
        return $Matches[1].ToUpper()
    }
    return $null
}

function Convert-WindowsPathToContainerPath {
    param([string]$Path)
    $text = ("$Path").Trim()
    if ($text -notmatch '^([A-Za-z]):[\\/]?(.*)$') { return $null }
    $letter = $Matches[1].ToLower()
    $rest = ($Matches[2] -replace '\\', '/').Trim('/')
    if (-not $rest) { return "/host/$letter" }
    return "/host/$letter/$rest"
}

function Resolve-ActiveComposeContext {
    $fallback = Join-Path $Root "docker-compose.yml"
    $base = $fallback
    $project = ""
    $configLabel = ""
    $activeFiles = @()
    $workingDir = ""

    try {
        $psRun = Invoke-NativeCapture -FilePath 'docker' -ArgumentList @('ps', '--filter', 'label=com.docker.compose.service=api', '--format', '{{.ID}}')
        $candidateIds = if ($psRun.ExitCode -eq 0) { @($psRun.Output) } else { @() }
        $selected = $null
        $selectedRank = 999
        $rootFull = [System.IO.Path]::GetFullPath($Root).TrimEnd('\')
        foreach ($candidate in $candidateIds) {
            $id = ("$candidate").Trim()
            if (-not $id) { continue }
            $inspectRun = Invoke-NativeCapture -FilePath 'docker' -ArgumentList @('inspect', $id)
            if ($inspectRun.ExitCode -ne 0 -or -not $inspectRun.Text) { continue }
            $obj = ($inspectRun.Text | ConvertFrom-Json)[0]
            $labels = $obj.Config.Labels
            $working = [string]$labels.'com.docker.compose.project.working_dir'
            $candidateProject = [string]$labels.'com.docker.compose.project'
            if ($working) {
                try { $working = [System.IO.Path]::GetFullPath($working).TrimEnd('\') } catch { }
            }
            $rank = Get-ProjectPreference -Project $candidateProject -WorkingDir $working -RootFull $rootFull
            if (-not $selected -or $rank -lt $selectedRank) {
                $selected = $obj
                $selectedRank = $rank
            }
        }

        if ($selected) {
            $labels = $selected.Config.Labels
            $configLabel = [string]$labels.'com.docker.compose.project.config_files'
            $project = [string]$labels.'com.docker.compose.project'
            $workingDir = [string]$labels.'com.docker.compose.project.working_dir'
            if ($workingDir) {
                try {
                    $workingDir = [System.IO.Path]::GetFullPath($workingDir).TrimEnd('\')
                    if (-not (Test-Path -LiteralPath $workingDir)) { $workingDir = "" }
                }
                catch { $workingDir = "" }
            }
            if ($configLabel) {
                foreach ($piece in @($configLabel -split ',')) {
                    $candidatePath = ("$piece").Trim().Trim('"')
                    if (-not $candidatePath) { continue }
                    if (-not [System.IO.Path]::IsPathRooted($candidatePath)) {
                        $candidatePath = Join-Path $Root $candidatePath
                    }
                    if (Test-IsDriveOverrideFile $candidatePath) {
                        continue
                    }
                    if (Test-Path -LiteralPath $candidatePath) {
                        $activeFiles += [System.IO.Path]::GetFullPath($candidatePath)
                    }
                }
            }
        }
    }
    catch { }

    if (-not $activeFiles.Count) {
        if ($configLabel -match 'docker-compose\.https\.yml') {
            $base = Join-Path $Root "docker-compose.https.yml"
        }
        if (-not (Test-Path -LiteralPath $base)) {
            throw "Active Compose base file not found: $base"
        }
        $activeFiles = @($base)
    }
    else {
        $base = $activeFiles[0]
    }

    $script:ComposeBase = $base
    $script:ComposeFiles = @($activeFiles | Select-Object -Unique)
    $script:ComposeProject = $project
    $script:ComposeWorkingDir = $(if ($workingDir) { $workingDir } else { [System.IO.Path]::GetFullPath($Root).TrimEnd('\') })
    $script:ComposeConfigLabel = $configLabel
    Set-RemountTarget -Project $project
}

function Ensure-ForensicComposeContext {
    # If inspect could not name the running project, still target the forensic
    # stack. Writing docker-compose.drives.generated.yml and composing without
    # -p aetheris-forensic leaves the extra disk invisible to extraction.
    if ($script:ComposeProject) { return }
    $probe = Invoke-NativeCapture -FilePath 'docker' -ArgumentList @(
        'ps', '-a',
        '--filter', 'label=com.docker.compose.project=aetheris-forensic',
        '--format', '{{.ID}}'
    )
    if ($probe.ExitCode -ne 0 -or -not ("$($probe.Text)").Trim()) { return }
    $script:ComposeProject = 'aetheris-forensic'
    Set-RemountTarget -Project 'aetheris-forensic'
    $forensicFile = Join-Path $Root "services\forensic\docker-compose.yml"
    if (Test-Path -LiteralPath $forensicFile) {
        $script:ComposeFiles = @([System.IO.Path]::GetFullPath($forensicFile))
        $script:ComposeBase = $script:ComposeFiles[0]
    }
}

function Get-OverrideHostLetters {
    param([string]$Path)
    $letters = @()
    if (-not $Path -or -not (Test-Path -LiteralPath $Path)) { return @() }
    foreach ($line in @(Get-Content -LiteralPath $Path -ErrorAction SilentlyContinue)) {
        if (("$line") -match 'target:\s*[''"]?/host/([a-zA-Z])(?:/|[''"]?\s*$)') {
            $letters += $Matches[1].ToUpper()
        }
    }
    return @($letters | Sort-Object -Unique)
}


function Get-StateMountTarget {
    param([hashtable]$State, [string]$Letter)
    $upper = ("$Letter").ToUpper()
    if ($State.ContainsKey($upper)) {
        $entry = $State[$upper]
        if ($entry.mount_target) { return [string]$entry.mount_target }
    }
    return "/host/$($upper.ToLower())"
}

function Test-IsExactPathMount {
    param([hashtable]$State, [string]$Letter)
    $upper = ("$Letter").ToUpper()
    if (-not $State.ContainsKey($upper)) { return $false }
    $entry = $State[$upper]
    return ([string]$entry.mode -eq 'docker-exact-path' -or [string]$entry.source_scope -eq 'selected-folder')
}

function Get-ComposeArgs {
    # Reuse the exact Compose file stack of the running API, then append only
    # the generated drive override. This preserves HTTPS/public/site overrides.
    $composeArgs = @('compose')
    if ($script:ComposeProject) {
        $composeArgs += @('-p', $script:ComposeProject)
    }
    # Match the project directory the stack was started with so root-relative
    # include: paths inside services/*/docker-compose.yml resolve correctly.
    $composeArgs += @('--project-directory', $script:ComposeWorkingDir)
    foreach ($file in @($script:ComposeFiles)) {
        $composeArgs += @('-f', $file)
    }
    $composeArgs += @('-f', $script:ComposeDrivesFile)
    return $composeArgs
}

function Get-ServiceContainerId {
    param([Parameter(Mandatory = $true)][string]$Service)
    $dockerArgs = @('ps', '--filter', "label=com.docker.compose.service=$Service")
    if ($script:ComposeProject) {
        $dockerArgs += @('--filter', "label=com.docker.compose.project=$($script:ComposeProject)")
    }
    $dockerArgs += @('--format', '{{.ID}}')
    $run = Invoke-NativeCapture -FilePath 'docker' -ArgumentList @($dockerArgs)
    if ($run.ExitCode -ne 0 -or -not $run.Output.Count) { return "" }
    return ("$($run.Output[0])").Trim()
}

function Invoke-ServicePythonProbe {
    param(
        [Parameter(Mandatory = $true)][string]$Service,
        [Parameter(Mandatory = $true)][string]$Code,
        [string]$Argument = ""
    )
    $id = Get-ServiceContainerId -Service $Service
    if (-not $id) { return $false }
    # Do not pass multiline Python through -c on Windows PowerShell 5.1.
    # Native-process argument quoting can remove quotes inside the Python code
    # (for example decode("utf-8") becomes decode(utf-8)). stdin is stable.
    $execArgs = @('exec', '-i', $id, 'python', '-')
    if ($Argument) { $execArgs += $Argument }
    $run = Invoke-NativeCapture -FilePath 'docker' -ArgumentList $execArgs -StdinText $Code
    return ($run.ExitCode -eq 0)
}

function Invoke-ApiPythonProbe {
    param(
        [Parameter(Mandatory = $true)][string]$Code,
        [string]$Argument = ""
    )
    return (Invoke-ServicePythonProbe -Service 'api' -Code $Code -Argument $Argument)
}

function Test-ContainerDriveMounts {
    param([string[]]$Letters)
    $missing = @()
    foreach ($letter in @($Letters)) {
        $l = $letter.ToLower()
        $code = @'
import pathlib, sys
p = sys.argv[1]
root = pathlib.Path(p)
mounted = False
try:
    lines = pathlib.Path('/proc/self/mountinfo').read_text(encoding='utf-8', errors='replace').splitlines()
    mounted = any(len(line.split()) > 4 and line.split()[4].replace('\\040', ' ') == p for line in lines)
except Exception:
    try:
        lines = pathlib.Path('/proc/mounts').read_text(encoding='utf-8', errors='replace').splitlines()
        mounted = any(len(line.split()) > 1 and line.split()[1].replace('\\040', ' ') == p for line in lines)
    except Exception:
        mounted = False
try:
    readable = root.is_dir()
    has_entries = False
    if readable:
        has_entries = next(root.iterdir(), None) is not None
except OSError:
    readable = False
    has_entries = False
# An empty /host/<letter> is Docker Desktop's stub for a newly attached
# removable drive, not a usable Windows volume.
raise SystemExit(0 if readable and mounted and has_entries else 2)
'@
        if (-not (Invoke-ApiPythonProbe -Code $code -Argument "/host/$l")) {
            $missing += $letter.ToUpper()
        }
    }
    return $missing
}

function Test-RequiredPathInContainer {
    param([string]$Path, [string]$Service = 'api')
    if (-not $Path) { return $true }
    $containerPath = Convert-WindowsPathToContainerPath $Path
    if (-not $containerPath) { return $false }
    $bytes = [System.Text.Encoding]::UTF8.GetBytes($containerPath)
    $b64 = [Convert]::ToBase64String($bytes)
    $code = @'
import base64, pathlib, sys
p = pathlib.Path(base64.b64decode(sys.argv[1]).decode('utf-8'))
if not p.exists():
    raise SystemExit(3)
if p.is_dir():
    next(p.iterdir(), None)
raise SystemExit(0)
'@
    return (Invoke-ServicePythonProbe -Service $Service -Code $code -Argument $b64)
}

function Wait-ApiHealthy {
    for ($i = 0; $i -lt 60; $i++) {
        $id = Get-ServiceContainerId -Service 'api'
        if ($id) {
            $run = Invoke-NativeCapture -FilePath 'docker' -ArgumentList @(
                'exec', $id, 'python', '-c',
                "import urllib.request; urllib.request.urlopen('http://127.0.0.1:8080/health', timeout=3)"
            )
            if ($run.ExitCode -eq 0) { return $true }
        }
        Start-Sleep -Seconds 3
    }
    return $false
}

function Read-SourceState {
    $state = @{}
    if (-not (Test-Path -LiteralPath $sourceStateFile)) { return $state }
    try {
        $obj = Get-Content -LiteralPath $sourceStateFile -Raw | ConvertFrom-Json
        $container = if ($obj.PSObject.Properties.Name -contains 'drives') { $obj.drives } else { $obj }
        if ($container) {
            foreach ($prop in $container.PSObject.Properties) {
                $letter = $prop.Name.ToUpper()
                if ($letter -notmatch '^[A-Z]$') { continue }
                $value = $prop.Value
                if (-not $value) { continue }
                if ($value -is [string]) {
                    $state[$letter] = @{ source = [string]$value; mode = 'legacy' }
                }
                elseif ($value.PSObject.Properties.Name -contains 'source') {
                    $state[$letter] = @{
                        source       = [string]$value.source
                        mode         = $(if ($value.mode) { [string]$value.mode } else { 'unknown' })
                        wsl_distro   = $(if ($value.wsl_distro) { [string]$value.wsl_distro } else { '' })
                        wsl_mount    = $(if ($value.wsl_mount) { [string]$value.wsl_mount } else { '' })
                        mount_target = $(if ($value.mount_target) { [string]$value.mount_target } else { '' })
                        source_scope = $(if ($value.source_scope) { [string]$value.source_scope } else { '' })
                        updated_utc  = $(if ($value.updated_utc) { [string]$value.updated_utc } else { '' })
                    }
                }
            }
        }
    }
    catch { }
    return $state
}

function Save-SourceState {
    param([hashtable]$State)
    $drives = @{}
    foreach ($key in @($State.Keys | Sort-Object)) {
        $drives[$key] = $State[$key]
    }
    $payload = @{
        version = 2
        drives = $drives
        updated_utc = (Get-Date).ToUniversalTime().ToString('o')
    }
    $json = $payload | ConvertTo-Json -Depth 8
    [System.IO.File]::WriteAllText($sourceStateFile, $json, [System.Text.UTF8Encoding]::new($false))
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

function Ensure-DaemonPathVolumes {
    param([hashtable]$State, [string[]]$Letters)
    $log = @()
    foreach ($letter in @($Letters)) {
        if (-not $State.ContainsKey($letter)) { continue }
        $source = [string]$State[$letter].source
        if (-not $source -or -not $source.StartsWith('/')) { continue }

        # Compose runs from Windows, while the verified WSL source is a path in
        # Docker's Linux daemon namespace.  Pre-create a uniquely named external
        # local volume so Compose cannot normalize the POSIX source into a fake
        # Windows path.  The source hash also avoids Docker Desktop's historical
        # local-volume option mismatch after path rewriting.
        $name = Get-DaemonVolumeName -Letter $letter -Source $source
        $inspectRun = Invoke-NativeCapture -FilePath 'docker' -ArgumentList @('volume', 'inspect', $name)
        if ($inspectRun.ExitCode -ne 0) {
            $createRun = Invoke-NativeCapture -FilePath 'docker' -ArgumentList @(
                'volume', 'create', '--driver', 'local', '--opt', 'type=none', '--opt', 'o=bind',
                '--opt', ("device={0}" -f $source), $name
            )
            if ($createRun.ExitCode -ne 0) {
                $detail = ($createRun.Output -join ' ')
                throw "Could not create Docker engine volume $name for ${letter}: source '$source'. $detail"
            }
            $log += "${letter}: created engine volume $name -> $source"
        }
        else {
            $log += "${letter}: engine volume ready $name -> $source"
        }
    }
    return $log
}

function Invoke-DriveSourceResolver {
    param(
        [Parameter(Mandatory = $true)][string]$Letter,
        [string]$ExactPath = "",
        [switch]$ForceWslBridge
    )
    if (-not (Test-Path -LiteralPath $resolveSourceScript)) {
        throw "Missing Docker drive source resolver: $resolveSourceScript"
    }
    $tmp = Join-Path $stateDir ("drive-source-{0}-{1}.json" -f $Letter.ToLower(), [guid]::NewGuid().ToString('N'))
    try {
        $psArgs = @(
            '-NoProfile', '-ExecutionPolicy', 'Bypass',
            '-File', $resolveSourceScript,
            '-DriveLetter', $Letter,
            '-Root', $Root,
            '-OutputFile', $tmp
        )
        if ($ExactPath) { $psArgs += @('-RequiredPath', $ExactPath) }
        if ($ForceWslBridge) { $psArgs += '-ForceWslBridge' }
        $run = Invoke-NativeCapture -FilePath 'powershell.exe' -ArgumentList $psArgs
        $exit = $run.ExitCode
        if (-not (Test-Path -LiteralPath $tmp)) {
            throw "Drive source resolver produced no result for ${Letter}:. $($run.Text -replace "`n", ' ')"
        }
        $result = Get-Content -LiteralPath $tmp -Raw | ConvertFrom-Json
        if ($exit -ne 0 -or -not $result.ok) {
            $msg = if ($result.error) { [string]$result.error } else { $run.Text }
            throw $msg
        }
        return $result
    }
    finally {
        Remove-Item -LiteralPath $tmp -Force -ErrorAction SilentlyContinue
    }
}

function Update-SourceStateEntry {
    param([hashtable]$State, [object]$Result)
    $letter = ([string]$Result.drive).ToUpper()
    $State[$letter] = @{
        source       = [string]$Result.source
        mode         = [string]$Result.mode
        wsl_distro   = $(if ($Result.wsl_distro) { [string]$Result.wsl_distro } else { '' })
        wsl_mount    = $(if ($Result.wsl_mount) { [string]$Result.wsl_mount } else { '' })
        mount_target = $(if ($Result.mount_target) { [string]$Result.mount_target } else { '' })
        source_scope = $(if ($Result.source_scope) { [string]$Result.source_scope } else { '' })
        updated_utc  = (Get-Date).ToUniversalTime().ToString('o')
    }
}

function Invoke-DriveGenerator {
    param(
        [string[]]$Required = @(),
        [string[]]$Excluded = @(),
        [ValidateSet('Windows','Wsl')][string]$ExecutionMode = 'Windows',
        [string]$OutputPath = '',
        [switch]$KeepRequiredForResolution
    )
    # Invoke the .ps1 directly so Windows PowerShell 5.1 can bind string[]
    # parameters correctly. powershell.exe -File cannot reliably pass multiple
    # values to an array parameter.
    try {
        $invokeParams = @{ SourceMapPath = $sourceStateFile; ExecutionMode = $ExecutionMode }
        if ($Required.Count) { $invokeParams.RequireDrive = @($Required) }
        if ($Excluded.Count) { $invokeParams.ExcludeDrive = @($Excluded) }
        if ($OutputPath) { $invokeParams.OutputPath = $OutputPath }
        else { $invokeParams.OutputPath = $script:ComposeDrivesFile }
        if ($KeepRequiredForResolution) { $invokeParams.KeepRequiredForResolution = $true }
        if ($script:RemountServices.Count) { $invokeParams.ServiceNames = @($script:RemountServices) }
        $output = & $generateScript @invokeParams 2>&1
    }
    catch {
        throw $_
    }
    $letters = @()
    foreach ($line in @($output | ForEach-Object { "$_" })) {
        if ($line -match '^Letters:\s*(.+)$') {
            $letters = @(
                ($Matches[1] -split ',\s*' | ForEach-Object { $_.Trim().ToUpper() }) |
                    Where-Object { $_ -match '^[A-Z]$' } |
                    Sort-Object -Unique
            )
        }
    }

    # Be defensive against PowerShell host/information-stream differences.
    # The generated Compose file is the source of truth, so recover drive letters
    # from its /host/<letter> targets if no machine-readable output was captured.
    $yamlPath = if ($OutputPath) { $OutputPath } else { $script:ComposeDrivesFile }
    if (-not $letters.Count -and (Test-Path -LiteralPath $yamlPath)) {
        $fromYaml = @()
        foreach ($yamlLine in @(Get-Content -LiteralPath $yamlPath -ErrorAction Stop)) {
            if (("$yamlLine") -match '^\s*target:\s*[''"]?/host/([a-zA-Z])(?:/|[''"]?\s*$)') {
                $fromYaml += $Matches[1].ToUpper()
            }
        }
        $letters = @($fromYaml | Sort-Object -Unique)
    }

    return @{
        output = @($output)
        letters = @($letters)
    }
}

function Convert-WindowsPathToWslPath {
    param(
        [Parameter(Mandatory = $true)][string]$Distro,
        [Parameter(Mandatory = $true)][string]$Path
    )
    try {
        $run = Invoke-NativeCapture -FilePath 'wsl.exe' -ArgumentList @('-d', $Distro, '--exec', 'wslpath', '-a', '-u', $Path)
        $text = if ($run.Output.Count) { ("$($run.Output[0])").Trim() } else { '' }
        if ($run.ExitCode -eq 0 -and $text.StartsWith('/')) { return $text }
    }
    catch { }
    $full = [System.IO.Path]::GetFullPath($Path)
    if ($full -notmatch '^([A-Za-z]):[\\/](.*)$') {
        throw "Cannot convert Windows path to WSL path: $Path"
    }
    $letter = $Matches[1].ToLower()
    $rest = ($Matches[2] -replace '\\', '/').Trim('/')
    if ($rest) { return "/mnt/$letter/$rest" }
    return "/mnt/$letter"
}

function Get-WslSourceForLetter {
    param([hashtable]$State, [string]$Letter)
    $upper = $Letter.ToUpper()
    $lower = $upper.ToLower()
    if ($State.ContainsKey($upper)) {
        $entry = $State[$upper]
        if ($entry.mode -eq 'wsl-compose' -and $entry.wsl_mount) {
            return [string]$entry.wsl_mount
        }
    }
    return "/mnt/$lower"
}

function Test-WslDriveSource {
    param([string]$Distro, [string]$Source)
    try {
        $run = Invoke-NativeCapture -FilePath 'wsl.exe' -ArgumentList @('-d', $Distro, '--exec', 'test', '-d', $Source)
        return ($run.ExitCode -eq 0)
    }
    catch { return $false }
}

function Test-ComposeProjectRunning {
    param([Parameter(Mandatory = $true)][string]$Project)
    $probe = Invoke-NativeCapture -FilePath 'docker' -ArgumentList @(
        'ps', '-q',
        '--filter', "label=com.docker.compose.project=$Project"
    )
    return ($probe.ExitCode -eq 0 -and ("$($probe.Text)").Trim())
}

function Update-SiblingProductDriveMounts {
    param(
        [string[]]$Required = @(),
        [string[]]$Excluded = @(),
        [ValidateSet('Windows', 'Wsl')][string]$ExecutionMode = 'Windows'
    )
    # Phone extraction runs in its own Compose project. Refreshing only the
    # forensic API leaves that worker on the previous mounts, so it reports
    # "missing /host/<letter>" for a folder Windows can already list.
    $products = @(
        @{
            Project  = 'aetheris-mobile-android'
            Compose  = Join-Path $Root 'services\mobile-android\docker-compose.yml'
            Drives   = Join-Path $Root 'docker-compose.drives.mobile-android.yml'
            Services = @('api', 'worker-build', 'worker-parse')
        },
        @{
            Project  = 'aetheris-mobile-ios'
            Compose  = Join-Path $Root 'services\mobile-ios\docker-compose.yml'
            Drives   = Join-Path $Root 'docker-compose.drives.mobile-ios.yml'
            Services = @('api', 'worker-build', 'worker-parse')
        },
        @{
            Project  = 'aetheris-mobile-extract'
            Compose  = Join-Path $Root 'services\mobile-extract\docker-compose.yml'
            Drives   = Join-Path $Root 'docker-compose.drives.mobile.yml'
            Services = @('api', 'worker-mobile')
        }
    )
    $savedServices = @($script:RemountServices)
    try {
        foreach ($product in $products) {
            if ($product.Project -eq $script:ComposeProject) { continue }
            if (-not (Test-Path -LiteralPath $product.Compose)) { continue }
            if (-not (Test-ComposeProjectRunning -Project $product.Project)) { continue }
            $script:RemountServices = @($product.Services)
            Invoke-DriveGenerator -Required $Required -Excluded $Excluded -ExecutionMode $ExecutionMode -OutputPath $product.Drives | Out-Null
            $cargs = @(
                'compose', '-p', $product.Project,
                '--project-directory', $script:ComposeWorkingDir,
                '-f', $product.Compose,
                '-f', $product.Drives,
                'up', '-d', '--no-deps', '--force-recreate'
            ) + @($product.Services)
            $up = Invoke-NativeCapture -FilePath 'docker' -ArgumentList $cargs
            if ($up.ExitCode -ne 0) {
                throw "Drive remount failed for $($product.Project): $($up.Output -join ' ')"
            }
            Write-Host "Remounted host drives into $($product.Project): $($product.Services -join ', ')"
        }
    }
    finally {
        $script:RemountServices = $savedServices
    }
}

function Recreate-ForensicServices {
    param([string]$WslDistro = "")

    if ($WslDistro) {
        $cargs = @('compose')
        if ($script:ComposeProject) { $cargs += @('-p', $script:ComposeProject) }
        $cargs += @('--project-directory', (Convert-WindowsPathToWslPath -Distro $WslDistro -Path $script:ComposeWorkingDir))
        foreach ($file in @($script:ComposeFiles)) {
            $cargs += @('-f', (Convert-WindowsPathToWslPath -Distro $WslDistro -Path $file))
        }
        $cargs += @('-f', (Convert-WindowsPathToWslPath -Distro $WslDistro -Path $composeDrivesWsl))

        $cfg = Invoke-NativeCapture -FilePath 'wsl.exe' -ArgumentList (@('-d', $WslDistro, '--exec', 'docker') + @($cargs) + @('config', '--quiet'))
        if ($cfg.ExitCode -ne 0) {
            throw "WSL Docker Compose validation failed in '$WslDistro': $($cfg.Output -join ' ')"
        }
        $up = Invoke-NativeCapture -FilePath 'wsl.exe' -ArgumentList (
            @('-d', $WslDistro, '--exec', 'docker') + @($cargs) +
            @('up', '-d', '--no-deps', '--force-recreate') + @($script:RemountServices)
        )
        if ($up.ExitCode -ne 0) {
            throw (Get-ComposeFailureDetail -Output $up.Output -ExitCode $up.ExitCode)
        }
        return @($up.Output)
    }

    $cargs = @(Get-ComposeArgs)
    $cfg = Invoke-NativeCapture -FilePath 'docker' -ArgumentList (@($cargs) + @('config', '--quiet'))
    if ($cfg.ExitCode -ne 0) {
        throw "Docker Compose validation failed: $($cfg.Output -join ' ')"
    }
    $up = Invoke-NativeCapture -FilePath 'docker' -ArgumentList (
        @($cargs) + @('up', '-d', '--no-deps', '--force-recreate') + @($script:RemountServices)
    )
    if ($up.ExitCode -ne 0) {
        throw (Get-ComposeFailureDetail -Output $up.Output -ExitCode $up.ExitCode)
    }
    return @($up.Output)
}

$requiredLetter = Get-RequiredDriveLetter $RequiredPath
$normalizedRequiredPath = if ($RequiredPath) { $RequiredPath.Trim() -replace '/', '\\' } else { "" }

Write-Status @{
    status      = 'running'
    ok          = $null
    message     = 'Detecting Windows drives and preparing Docker-readable mounts...'
    drives      = @()
    error       = $null
    log         = ''
    started_utc = (Get-Date).ToUniversalTime().ToString('o')
}

try {
    if (-not (Test-Path -LiteralPath $generateScript)) {
        throw "Missing script: $generateScript"
    }
    if (-not (Test-Path -LiteralPath $resolveSourceScript)) {
        throw "Missing script: $resolveSourceScript"
    }

    Resolve-ActiveComposeContext
    Ensure-ForensicComposeContext

    $lettersBeforeGenerate = @(Get-OverrideHostLetters $script:ComposeDrivesFile)

    if ($normalizedRequiredPath) {
        if (-not $requiredLetter) {
            throw "RequiredPath must be an absolute Windows drive path such as G:\Evidence\Case01. Received: $RequiredPath"
        }
        if (-not (Test-Path -LiteralPath $normalizedRequiredPath)) {
            throw "Windows can no longer see the selected path: $normalizedRequiredPath. Reconnect the drive and select the folder again."
        }
    }

    Start-Sleep -Seconds 1

    # First pass detects the current Windows drive letters.  It may write direct
    # defaults, but no containers are recreated until every usable source below
    # has been resolved and the final override is regenerated.
    if (-not (Test-Path -LiteralPath $sourceStateFile)) {
        Save-SourceState -State @{}
    }
    # Discovery writes to a disposable override. The selected removable drive
    # may intentionally be unbindable at its root until exact-path resolution
    # succeeds, so never overwrite the active Compose override with that
    # provisional source.
    $first = Invoke-DriveGenerator `
        -Required $(if ($requiredLetter) { @($requiredLetter) } else { @() }) `
        -KeepRequiredForResolution `
        -OutputPath $detectCompose
    $detectedLetters = @($first.letters)
    if (-not $detectedLetters.Count) {
        throw 'Drive generator returned no drive letters.'
    }

    Write-Status @{
        status  = 'running'
        ok      = $null
        message = $(if ($requiredLetter) {
            "Testing Docker access to all detected drives; selected path: $normalizedRequiredPath"
        } else {
            'Testing Docker access to detected Windows drives...'
        })
        drives  = $detectedLetters
        error   = $null
        log     = (($first.output | ForEach-Object { "$_" }) -join "`n")
    }

    $sourceState = Read-SourceState
    $excluded = @()
    $resolutionLog = @()
    $resolutionByLetter = @{}
    $requiredResolution = $null

    # Resolve the required drive first with the exact selected path.  Other
    # drives are resolved against a real root sentinel so one broken/unshared
    # auxiliary drive cannot make the selected evidence path fail.
    $orderedLetters = @()
    if ($requiredLetter -and $detectedLetters -contains $requiredLetter) {
        $orderedLetters += $requiredLetter
    }
    $orderedLetters += @($detectedLetters | Where-Object { $_ -ne $requiredLetter })

    foreach ($letter in $orderedLetters) {
        $exact = if ($letter -eq $requiredLetter) { $normalizedRequiredPath } else { '' }
        try {
            $resolved = Invoke-DriveSourceResolver -Letter $letter -ExactPath $exact
            Update-SourceStateEntry -State $sourceState -Result $resolved
            $resolutionByLetter[$letter] = $resolved
            if ($letter -eq $requiredLetter) { $requiredResolution = $resolved }
            $resolutionLog += ("{0}: mode={1} source={2} distro={3}" -f $letter, [string]$resolved.mode, [string]$resolved.source, [string]$resolved.wsl_distro)
        }
        catch {
            if ($letter -eq $requiredLetter) { throw }
            $excluded += $letter
            $resolutionLog += "${letter}: skipped - $($_.Exception.Message)"
        }
    }

    Save-SourceState -State $sourceState

    # If any required/active drive needs WSL, run Compose from the SAME
    # Docker-Desktop-integrated WSL distro that successfully passed the exact
    # docker-run probe. This is the critical difference from v4.3: a DrvFs
    # mount in Ubuntu is not assumed to exist in docker-desktop's daemon mount
    # namespace. Docker Desktop itself translates the WSL bind when the client
    # runs through its WSL integration.
    $wslDistro = ""
    if ($requiredResolution -and $requiredResolution.mode -eq 'wsl-compose' -and $requiredResolution.wsl_distro) {
        $wslDistro = [string]$requiredResolution.wsl_distro
    }
    if (-not $wslDistro) {
        foreach ($key in @($resolutionByLetter.Keys | Sort-Object)) {
            $candidate = $resolutionByLetter[$key]
            if ($candidate.mode -eq 'wsl-compose' -and $candidate.wsl_distro) {
                $wslDistro = [string]$candidate.wsl_distro
                break
            }
        }
    }

    if ($wslDistro) {
        # Auxiliary drives must also be visible from the chosen WSL distro
        # because the WSL-generated override uses /mnt/<letter> for direct
        # drives. Skip inaccessible auxiliary drives; never skip the selected one.
        foreach ($letter in @($detectedLetters)) {
            if ($excluded -contains $letter) { continue }
            $wslSource = Get-WslSourceForLetter -State $sourceState -Letter $letter
            if (-not (Test-WslDriveSource -Distro $wslDistro -Source $wslSource)) {
                if ($letter -eq $requiredLetter) {
                    throw "Selected drive ${letter}: was resolved through WSL but source '$wslSource' is no longer visible in distro '$wslDistro'."
                }
                $excluded += $letter
                $resolutionLog += "${letter}: skipped in WSL compose - source '$wslSource' is not visible in '$wslDistro'"
            }
        }
        $excluded = @($excluded | Sort-Object -Unique)
        $final = Invoke-DriveGenerator `
            -Required $(if ($requiredLetter) { @($requiredLetter) } else { @() }) `
            -Excluded @($excluded) `
            -ExecutionMode Wsl `
            -OutputPath $composeDrivesWsl
        $resolutionLog += "Compose execution: WSL distro '$wslDistro' using $composeDrivesWsl"
    }
    else {
        $final = Invoke-DriveGenerator `
            -Required $(if ($requiredLetter) { @($requiredLetter) } else { @() }) `
            -Excluded @($excluded)
        $engineVolumeLog = @(Ensure-DaemonPathVolumes -State $sourceState -Letters @($final.letters))
        foreach ($line in $engineVolumeLog) { $resolutionLog += $line }
    }

    $letters = @($final.letters)
    if ($requiredLetter -and ($letters -notcontains $requiredLetter)) {
        throw "Required drive ${requiredLetter}: was not included in the final Docker mounts."
    }

    # We intentionally resolve sources before deciding whether a recreate is
    # necessary. The exact selected path, not merely /host/<letter>, is the
    # authority for stale/removable-drive detection.

    Push-Location $Root
    try {
        $verifyLetters = if ($requiredLetter) { @($requiredLetter) } else { @($letters) }
        $exactRequiredMount = [bool]($requiredLetter -and (Test-IsExactPathMount -State $sourceState -Letter $requiredLetter))
        $rootVerifyLetters = if ($exactRequiredMount -and $requiredLetter) {
            @($verifyLetters | Where-Object { $_ -ne $requiredLetter })
        } else {
            @($verifyLetters)
        }
        $missingBefore = @()
        if ($rootVerifyLetters.Count) {
            try { $missingBefore = @(Test-ContainerDriveMounts -Letters $rootVerifyLetters) }
            catch { $missingBefore = @($rootVerifyLetters) }
        }

        $requiredVisible = $true
        if ($normalizedRequiredPath) {
            try { $requiredVisible = Test-RequiredPathInContainer -Path $normalizedRequiredPath }
            catch { $requiredVisible = $false }
        }

        # Compare the currently running container mount sources with the final
        # desired sources instead of relying only on YAML file timestamps. An
        # exact-folder mount intentionally has no /host/G root mount; the exact
        # evidence path is the authority in that mode.
        $mustRecreate = $missingBefore.Count -gt 0 -or -not $requiredVisible
        if ($requiredLetter -and ($lettersBeforeGenerate -notcontains $requiredLetter)) {
            $mustRecreate = $true
            $resolutionLog += "Required drive ${requiredLetter}: was not in $($script:ComposeDrivesFile) - forcing service recreate."
        }
        if (-not $mustRecreate) {
            # A source can change while /host/g remains mounted.  Ask Docker
            # inspect whether the source matches the desired state for the
            # required drive; if unsure, recreate safely.
            if ($requiredLetter -and $sourceState.ContainsKey($requiredLetter)) {
                try {
                    $apiId = Get-ServiceContainerId -Service 'api'
                    $inspectRun = Invoke-NativeCapture -FilePath 'docker' -ArgumentList @('inspect', $apiId)
                    if ($inspectRun.ExitCode -ne 0 -or -not $inspectRun.Text) { throw "docker inspect failed for api container $apiId" }
                    $inspect = ($inspectRun.Text | ConvertFrom-Json)[0]
                    $target = Get-StateMountTarget -State $sourceState -Letter $requiredLetter
                    $actual = @($inspect.Mounts | Where-Object { $_.Destination -eq $target } | Select-Object -First 1)
                    if (-not $actual -or -not $actual[0].Source) {
                        $mustRecreate = $true
                    }
                }
                catch { $mustRecreate = $true }
            }
        }

        if ($mustRecreate) {
            Write-Status @{
                status  = 'running'
                ok      = $null
                message = $(if ($requiredResolution -and $requiredResolution.mode -eq 'wsl-compose') {
                    "Docker Desktop direct sharing was stale. Recreating forensic services through the automatic WSL bridge for ${requiredLetter}:..."
                } else {
                    'Recreating forensic services with verified dynamic drive mounts...'
                })
                drives  = $letters
                mount_mode = $(if ($requiredResolution) { [string]$requiredResolution.mode } else { $null })
                mount_source = $(if ($requiredResolution) { [string]$requiredResolution.source } else { $null })
                wsl_distro = $(if ($requiredResolution -and $requiredResolution.wsl_distro) { [string]$requiredResolution.wsl_distro } else { $null })
                error   = $null
                log     = ((@($resolutionLog) + @($final.output)) -join "`n")
            }

            $composeOutput = @(Recreate-ForensicServices -WslDistro $wslDistro)
            Update-SiblingProductDriveMounts -Required @($letters) -Excluded @($excluded) -ExecutionMode $(if ($wslDistro) { 'Wsl' } else { 'Windows' })
            Write-Status @{
                status  = 'running'
                ok      = $null
                message = 'Waiting for API health after drive remount...'
                drives  = $letters
                mount_mode = $(if ($requiredResolution) { [string]$requiredResolution.mode } else { $null })
                mount_source = $(if ($requiredResolution) { [string]$requiredResolution.source } else { $null })
                wsl_distro = $(if ($requiredResolution -and $requiredResolution.wsl_distro) { [string]$requiredResolution.wsl_distro } else { $null })
                error   = $null
                log     = ((@($resolutionLog) + @($final.output) + @($composeOutput)) -join "`n")
            }
            if (-not (Wait-ApiHealthy)) {
                throw 'API container did not become healthy within 3 minutes after drive remount.'
            }
        }
        else {
            $composeOutput = @('Existing container mount already satisfies the selected path.')
        }

        $missingAfter = @()
        if ($rootVerifyLetters.Count) {
            $missingAfter = @(Test-ContainerDriveMounts -Letters $rootVerifyLetters)
        }
        if ($missingAfter.Count) {
            throw "Docker did not attach required drive mount(s): $($missingAfter -join ', ')."
        }

        if ($normalizedRequiredPath -and -not (Test-RequiredPathInContainer -Path $normalizedRequiredPath)) {
            # One final forced WSL fallback handles the case where a direct
            # docker-run probe works but Compose/Docker Desktop path translation
            # still yields a stale mount in the long-running service.
            if (-not $requiredResolution -or $requiredResolution.mode -ne 'wsl-compose') {
                Write-Status @{
                    status = 'running'; ok = $null; drives = $letters; error = $null
                    message = "Direct mount still stale in Compose; switching ${requiredLetter}: to WSL DrvFs fallback..."
                    log = ((@($resolutionLog) + @($final.output) + @($composeOutput)) -join "`n")
                }
                $forced = Invoke-DriveSourceResolver `
                    -Letter $requiredLetter `
                    -ExactPath $normalizedRequiredPath `
                    -ForceWslBridge
                Update-SourceStateEntry -State $sourceState -Result $forced
                Save-SourceState -State $sourceState
                $requiredResolution = $forced
                $resolutionByLetter[$requiredLetter] = $forced
                if ($forced.mode -eq 'wsl-compose' -and $forced.wsl_distro) {
                    $wslDistro = [string]$forced.wsl_distro
                    foreach ($letter in @($detectedLetters)) {
                        if ($excluded -contains $letter) { continue }
                        $wslSource = Get-WslSourceForLetter -State $sourceState -Letter $letter
                        if (-not (Test-WslDriveSource -Distro $wslDistro -Source $wslSource)) {
                            if ($letter -eq $requiredLetter) {
                                throw "Forced WSL source '$wslSource' for ${letter}: disappeared before Compose recreation."
                            }
                            $excluded += $letter
                        }
                    }
                    $excluded = @($excluded | Sort-Object -Unique)
                    $final = Invoke-DriveGenerator -Required @($requiredLetter) -Excluded @($excluded) `
                        -ExecutionMode Wsl -OutputPath $composeDrivesWsl
                }
                else {
                    $wslDistro = ""
                    $final = Invoke-DriveGenerator -Required @($requiredLetter) -Excluded @($excluded)
                    $engineVolumeLog2 = @(Ensure-DaemonPathVolumes -State $sourceState -Letters @($final.letters))
                    foreach ($line in $engineVolumeLog2) { $resolutionLog += $line }
                }
                $letters = @($final.letters)
                $composeOutput2 = @(Recreate-ForensicServices -WslDistro $wslDistro)
                Update-SiblingProductDriveMounts -Required @($letters) -Excluded @($excluded) -ExecutionMode $(if ($wslDistro) { 'Wsl' } else { 'Windows' })
                if (-not (Wait-ApiHealthy)) {
                    throw 'API did not become healthy after WSL bridge remount.'
                }
                if (-not (Test-RequiredPathInContainer -Path $normalizedRequiredPath)) {
                    throw "Automatic WSL bridge was created, but Docker still cannot read '$normalizedRequiredPath'."
                }
                $composeOutput += $composeOutput2
            }
            else {
                throw "Automatic WSL bridge is active, but Docker cannot read '$normalizedRequiredPath'."
            }
        }

        # The pipeline runs in workers, not only in the API. Do not report the
        # selected path ready until every forensic service can actually read it.
        if ($normalizedRequiredPath) {
            foreach ($service in @($script:RemountServices)) {
                if (-not (Test-RequiredPathInContainer -Path $normalizedRequiredPath -Service $service)) {
                    throw "${service} cannot read the selected evidence path '$normalizedRequiredPath' after remount."
                }
            }
        }
    }
    finally {
        Pop-Location
    }

    Write-Status @{
        status       = 'done'
        ok           = $true
        unchanged    = (-not $mustRecreate -and -not ($composeOutput.Count -gt 1))
        drives       = $letters
        skipped_drives = @($excluded)
        mount_mode   = $(if ($requiredResolution) { [string]$requiredResolution.mode } else { $null })
        mount_source = $(if ($requiredResolution) { [string]$requiredResolution.source } else { $null })
        wsl_distro   = $(if ($requiredResolution -and $requiredResolution.wsl_distro) { [string]$requiredResolution.wsl_distro } else { $null })
        message      = $(if ($normalizedRequiredPath) {
            if ($requiredResolution -and $requiredResolution.mode -eq 'wsl-compose') {
                "Selected path is visible in Docker through the automatic WSL bridge: $normalizedRequiredPath"
            } else {
                "Selected path is visible in Docker: $normalizedRequiredPath"
            }
        } else {
            "Dynamic drive mounts ready: $($letters -join ', ')."
        })
        error        = $null
        log          = ((@($resolutionLog) + @($final.output) + @($composeOutput)) -join "`n")
        finished_utc = (Get-Date).ToUniversalTime().ToString('o')
    }
    exit 0
}
catch {
    Write-Status @{
        status       = 'error'
        ok           = $false
        drives       = @()
        message      = 'Drive mount refresh failed'
        error        = $_.Exception.Message
        log          = $_.Exception.Message
        finished_utc = (Get-Date).ToUniversalTime().ToString('o')
    }
    exit 1
}
