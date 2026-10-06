<#
.SYNOPSIS
  End-to-end Windows/Docker validation for automatic forensic drive mounting.

.EXAMPLE
  powershell -ExecutionPolicy Bypass -File scripts\test-dynamic-drive-mounts.ps1 `
    -RequiredPath "G:\Ex.1 Darshan SSD 256"

The test uses the same refresh job as the app. It accepts any drive letter A:..Z:,
automatically falls back to the WSL DrvFs bridge when Docker Desktop exposes a
stale/empty removable-drive mount, and verifies the exact selected path in all
forensic services. No evidence is copied or modified.
#>
param(
    [Parameter(Mandatory = $true)][string]$RequiredPath
)

$ErrorActionPreference = "Stop"
$env:COMPOSE_ANSI = "never"
$env:DOCKER_CLI_HINTS = "false"

function Convert-NativeOutputToLines {
    param($Output)
    $lines = @()
    $esc = [char]27
    foreach ($item in @($Output)) {
        if ($null -eq $item) { continue }
        $text = if ($item -is [System.Management.Automation.ErrorRecord]) { [string]$item.Exception.Message } else { [string]$item }
        $text = ($text -replace "$esc\[[0-9;?]*[ -/]*[@-~]", '') -replace "`0", ''
        foreach ($piece in ($text -split "`r?`n")) {
            $trimmed = $piece.TrimEnd()
            if ($trimmed.Trim()) { $lines += $trimmed }
        }
    }
    return @($lines)
}

function Invoke-NativeCapture {
    # Windows PowerShell 5.1 turns the first redirected stderr line of a native
    # command into a terminating error under $ErrorActionPreference = "Stop".
    # docker/compose write warnings and progress on stderr, so run native
    # commands with the preference relaxed for the call only and decide on
    # the exit code.
    param(
        [Parameter(Mandatory = $true)][string]$FilePath,
        [string[]]$ArgumentList = @(),
        [string]$StdinText = ""
    )
    $ErrorActionPreference = "Continue"
    $global:LASTEXITCODE = 0
    $raw = @(); $code = 0
    $feedStdin = $PSBoundParameters.ContainsKey('StdinText')
    try {
        if ($feedStdin) { $raw = @($StdinText | & $FilePath @ArgumentList 2>&1) }
        else { $raw = @(& $FilePath @ArgumentList 2>&1) }
        $code = if ($null -ne $LASTEXITCODE) { [int]$LASTEXITCODE } else { 0 }
    }
    catch {
        $raw = @($raw) + @($_.Exception.Message); $code = -1
    }
    $global:LASTEXITCODE = $code
    $lines = @(Convert-NativeOutputToLines $raw)
    return @{ ExitCode = $code; Output = $lines; Text = ($lines -join "`n") }
}

function Get-ProjectPreference {
    # Same ranking as refresh-drive-mounts-job.ps1: the forensic stack owns the
    # disk pipeline; mobile-extract is second; the vuln stack never has the
    # forensic workers and must not be selected just because its api container
    # was listed first.
    param([string]$Project, [string]$WorkingDir, [string]$RootFull)
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
    if ($name -eq 'aetheris-vuln') { return 90 }
    if ($name -eq 'rag_new2') { return 80 }
    if ($rootMatch) { return 10 }
    return 50
}

function Get-ForensicServicesForProject {
    # Services that must see the evidence path, per split stack
    # (mirrors Set-RemountTarget in refresh-drive-mounts-job.ps1).
    param([string]$Project)
    switch (("$Project").Trim()) {
        'aetheris-forensic'       { return @('api', 'worker-disk', 'worker-parse', 'worker-report') }
        'aetheris-mobile-android' { return @('api', 'worker-build', 'worker-parse') }
        'aetheris-mobile-ios'     { return @('api', 'worker-build', 'worker-parse') }
        'aetheris-mobile-extract' { return @('api', 'worker-mobile') }
        default                   { return @('api', 'worker-disk', 'worker-parse', 'worker-mobile', 'worker-report') }
    }
}
$root = Split-Path -Parent (Split-Path -Parent $MyInvocation.MyCommand.Path)
$drives = Join-Path $root "docker-compose.drives.generated.yml"
$wslDrives = Join-Path $root "docker-compose.drives.wsl.generated.yml"

function Get-DriveOverrideForProject {
    # Mirrors Set-RemountTarget in refresh-drive-mounts-job.ps1. Each split stack
    # has its own generated override with ONLY its services; the monolithic
    # docker-compose.drives.generated.yml (api/worker-disk/worker-mobile/
    # worker-report) must never be layered onto a split stack or Compose fails
    # with: service "worker-mobile" has neither an image nor a build context.
    param([string]$Project)
    switch (("$Project").Trim()) {
        'aetheris-forensic'       { return (Join-Path $root "docker-compose.drives.forensic.yml") }
        'aetheris-mobile-android' { return (Join-Path $root "docker-compose.drives.mobile-android.yml") }
        'aetheris-mobile-ios'     { return (Join-Path $root "docker-compose.drives.mobile-ios.yml") }
        'aetheris-mobile-extract' { return (Join-Path $root "docker-compose.drives.mobile.yml") }
        default                   { return $drives }
    }
}

function Test-IsDriveOverrideFile([string]$Path) {
    return ((Split-Path -Leaf $Path) -match '^docker-compose\.drives(\.|$)')
}
$refresh = Join-Path $root "scripts\refresh-drive-mounts-job.ps1"
$status = Join-Path $env:TEMP ("aetheris-drive-test-" + [guid]::NewGuid().ToString("N") + ".json")

function Get-ActiveComposeContext {
    $files = @()
    $project = ""
    $workingDir = ""
    $selectedContainer = $null
    $selectedRank = 999
    $rootFull = [System.IO.Path]::GetFullPath($root).TrimEnd('\')
    $psRun = Invoke-NativeCapture -FilePath 'docker' -ArgumentList @('ps', '--filter', 'label=com.docker.compose.service=api', '--format', '{{.ID}}')
    $ids = if ($psRun.ExitCode -eq 0) { @($psRun.Output) } else { @() }
    foreach ($candidate in $ids) {
        $id = ("$candidate").Trim()
        if (-not $id) { continue }
        try {
            $inspectRun = Invoke-NativeCapture -FilePath 'docker' -ArgumentList @('inspect', $id)
            if ($inspectRun.ExitCode -ne 0 -or -not $inspectRun.Text) { continue }
            $obj = ($inspectRun.Text | ConvertFrom-Json)[0]
            $working = [string]$obj.Config.Labels.'com.docker.compose.project.working_dir'
            if ($working) {
                try { $working = [System.IO.Path]::GetFullPath($working).TrimEnd('\') } catch { }
            }
            $candidateProject = [string]$obj.Config.Labels.'com.docker.compose.project'
            $rank = Get-ProjectPreference -Project $candidateProject -WorkingDir $working -RootFull $rootFull
            if (-not $selectedContainer -or $rank -lt $selectedRank) {
                $selectedContainer = $obj
                $selectedRank = $rank
            }
        }
        catch { }
    }
    if ($selectedContainer) {
        $project = [string]$selectedContainer.Config.Labels.'com.docker.compose.project'
        $workingDir = [string]$selectedContainer.Config.Labels.'com.docker.compose.project.working_dir'
        if ($workingDir) {
            try {
                $workingDir = [System.IO.Path]::GetFullPath($workingDir).TrimEnd('\')
                if (-not (Test-Path -LiteralPath $workingDir)) { $workingDir = "" }
            }
            catch { $workingDir = "" }
        }
        $cfg = [string]$selectedContainer.Config.Labels.'com.docker.compose.project.config_files'
        foreach ($part in @($cfg -split ',')) {
            $file = ("$part").Trim().Trim('"')
            if (-not $file) { continue }
            if (-not [System.IO.Path]::IsPathRooted($file)) { $file = Join-Path $root $file }
            # Drop every drives override from the label; the project-specific
            # one is re-appended by Get-ComposeArgs (same as the refresh job).
            if (Test-IsDriveOverrideFile $file) { continue }
            if (Test-Path -LiteralPath $file) { $files += [System.IO.Path]::GetFullPath($file) }
        }
    }
    if (-not $files.Count) { $files = @(Join-Path $root 'docker-compose.yml') }
    if (-not $workingDir) { $workingDir = $rootFull }
    return @{ files = @($files | Select-Object -Unique); project = $project; working_dir = $workingDir }
}

function Get-ComposeArgs([hashtable]$Context) {
    $args = @('compose')
    if ($Context.project) { $args += @('-p', [string]$Context.project) }
    # The split stacks (services/*/docker-compose.yml) use root-relative
    # include: paths and were started with "--project-directory .". Compose
    # otherwise defaults the project dir to the first -f file's folder and
    # fails with "open ...\services\vuln\docker-compose.gvm.yml: not found".
    $args += @('--project-directory', [string]$Context.working_dir)
    foreach ($file in @($Context.files)) { $args += @('-f', [string]$file) }
    $override = Get-DriveOverrideForProject -Project ([string]$Context.project)
    if (-not (Test-Path -LiteralPath $override)) { throw "Drive override for project '$($Context.project)' was not generated: $override" }
    $args += @('-f', $override)
    return $args
}


function Convert-WindowsPathToWslPath {
    param([string]$Distro, [string]$Path)
    try {
        $run = Invoke-NativeCapture -FilePath 'wsl.exe' -ArgumentList @('-d', $Distro, '--exec', 'wslpath', '-a', '-u', $Path)
        $text = if ($run.Output.Count) { ("$($run.Output[0])").Trim() } else { '' }
        if ($run.ExitCode -eq 0 -and $text.StartsWith('/')) { return $text }
    }
    catch { }
    $full = [System.IO.Path]::GetFullPath($Path)
    if ($full -notmatch '^([A-Za-z]):[\/](.*)$') { throw "Cannot convert path to WSL: $Path" }
    $l = $Matches[1].ToLower()
    $rest = ($Matches[2] -replace '\\', '/').Trim('/')
    if ($rest) { return "/mnt/$l/$rest" }
    return "/mnt/$l"
}

function Get-ServiceContainerId {
    param([string]$Service, [string]$Project)
    $dockerArgs = @('ps', '--filter', "label=com.docker.compose.service=$Service")
    if ($Project) { $dockerArgs += @('--filter', "label=com.docker.compose.project=$Project") }
    $dockerArgs += @('--format', '{{.ID}}')
    $run = Invoke-NativeCapture -FilePath 'docker' -ArgumentList @($dockerArgs)
    if ($run.ExitCode -ne 0 -or -not $run.Output.Count) { return "" }
    return ("$($run.Output[0])").Trim()
}

$selected = $RequiredPath.Trim() -replace '/', '\'
if ($selected -notmatch '^([A-Za-z]):[\\/]') {
    throw "RequiredPath must be an absolute Windows path such as G:\Evidence\Case01."
}
$letter = $Matches[1].ToLower()
if (-not (Test-Path -LiteralPath $selected)) {
    throw "Windows cannot see the selected path: $selected"
}

function Convert-ToContainerPath([string]$Path) {
    if ($Path -notmatch '^([A-Za-z]):[\\/]?(.*)$') { return $null }
    $l = $Matches[1].ToLower()
    $rest = ($Matches[2] -replace '\\', '/').Trim('/')
    if ($rest) { return "/host/$l/$rest" }
    return "/host/$l"
}

$containerPath = Convert-ToContainerPath $selected
$pathB64 = [Convert]::ToBase64String([Text.Encoding]::UTF8.GetBytes($containerPath))
$probeCode = @'
import base64, pathlib, sys
p = pathlib.Path(base64.b64decode(sys.argv[1]).decode("utf-8"))
print(p)
if not p.exists():
    raise SystemExit(3)
if p.is_dir():
    next(p.iterdir(), None)
raise SystemExit(0)
'@

Push-Location $root
try {
    Write-Host "[1/4] Windows path OK: $selected"
    Write-Host "[2/4] Running the same automatic mount recovery used by the app ..."
    & powershell -NoProfile -ExecutionPolicy Bypass -File $refresh `
        -Root $root -StatusFile $status -RequiredPath $selected
    if ($LASTEXITCODE -ne 0) {
        $detail = if (Test-Path -LiteralPath $status) { Get-Content -LiteralPath $status -Raw } else { "" }
        throw "Dynamic drive refresh failed. $detail"
    }

    $state = Get-Content -LiteralPath $status -Raw | ConvertFrom-Json
    Write-Host ("      mode={0}" -f $state.mount_mode)
    if ($state.mount_source) { Write-Host ("      source={0}" -f $state.mount_source) }
    if ($state.wsl_distro) { Write-Host ("      wsl_distro={0}" -f $state.wsl_distro) }

    $ctx = Get-ActiveComposeContext
    $baseNames = ((@($ctx.files) + @(Get-DriveOverrideForProject -Project ([string]$ctx.project))) | ForEach-Object { Split-Path -Leaf $_ }) -join ', '
    if ($ctx.project) { Write-Host ("      project={0}  project-directory={1}" -f $ctx.project, $ctx.working_dir) }

    Write-Host "[3/4] Validating merged Compose configuration: $baseNames"
    if ($state.mount_mode -eq 'wsl-compose') {
        if (-not $state.wsl_distro) { throw "WSL compose mode is active but wsl_distro is missing from refresh state." }
        if (-not (Test-Path -LiteralPath $wslDrives)) { throw "Missing WSL drive override: $wslDrives" }
        $wslArgs = @('compose')
        if ($ctx.project) { $wslArgs += @('-p', [string]$ctx.project) }
        $wslArgs += @('--project-directory', (Convert-WindowsPathToWslPath -Distro ([string]$state.wsl_distro) -Path ([string]$ctx.working_dir)))
        foreach ($file in @($ctx.files)) {
            $wslArgs += @('-f', (Convert-WindowsPathToWslPath -Distro ([string]$state.wsl_distro) -Path $file))
        }
        $wslArgs += @('-f', (Convert-WindowsPathToWslPath -Distro ([string]$state.wsl_distro) -Path $wslDrives))
        $cfg = Invoke-NativeCapture -FilePath 'wsl.exe' -ArgumentList (@('-d', [string]$state.wsl_distro, '--exec', 'docker') + @($wslArgs) + @('config', '--quiet'))
        if ($cfg.ExitCode -ne 0) { throw "WSL docker compose config validation failed. $($cfg.Text)" }
    }
    else {
        $composeArgs = @(Get-ComposeArgs -Context $ctx)
        $cfg = Invoke-NativeCapture -FilePath 'docker' -ArgumentList (@($composeArgs) + @('config', '--quiet'))
        if ($cfg.ExitCode -ne 0) { throw "docker compose config validation failed. $($cfg.Text)" }
    }

    $services = @(Get-ForensicServicesForProject -Project ([string]$ctx.project))
    Write-Host "[4/4] Verifying exact path in every forensic service ($($services -join ', ')): $containerPath"
    foreach ($service in $services) {
        $id = Get-ServiceContainerId -Service $service -Project ([string]$ctx.project)
        if (-not $id) { throw "Running container not found for service $service in project '$($ctx.project)'" }
        # Windows PowerShell 5.1 can strip embedded quotes from a multiline
        # python -c argument when invoking a native executable. Feed the probe
        # through stdin instead so Python receives the script byte-for-byte.
        $probe = Invoke-NativeCapture -FilePath 'docker' -ArgumentList @('exec', '-i', $id, 'python', '-', $pathB64) -StdinText $probeCode
        if ($probe.ExitCode -ne 0) { throw "$service cannot read $containerPath (exit $($probe.ExitCode)). $($probe.Text)" }
        Write-Host "      PASS $service"
    }

    Write-Host ""
    Write-Host "PASS: $selected is visible read-only to all forensic services." -ForegroundColor Green
    if ($state.mount_mode -eq 'wsl-compose') {
        Write-Host "Docker Desktop's stale Windows-drive share was bypassed through Docker Desktop WSL Integration." -ForegroundColor Green
    }
}
finally {
    Pop-Location
    Remove-Item -LiteralPath $status -Force -ErrorAction SilentlyContinue
}
