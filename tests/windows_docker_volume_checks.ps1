param([string]$ProjectRoot = (Split-Path -Parent $PSScriptRoot))
$ErrorActionPreference = 'Stop'
. (Join-Path $ProjectRoot 'scripts/docker-engine-recovery.ps1')
$script:checks = 0
$script:mode = 'missing'
$script:calls = New-Object System.Collections.Generic.List[object]
function Assert-True([bool]$Value, [string]$Message) {
    if (-not $Value) { throw "FAIL: $Message" }
    $script:checks++
}
function MockDocker {
    $call = @($args)
    $script:calls.Add($call)
    if ($call[1] -eq 'create') {
        $global:LASTEXITCODE = if ($script:mode -eq 'create-fail') { 1 } else { 0 }
        if ($global:LASTEXITCODE) { Write-Error 'permission denied during create' }
        return
    }
    switch ($script:mode) {
        'present' { $global:LASTEXITCODE=0; return '{}' }
        'healthy-stderr' { $global:LASTEXITCODE=0; Write-Error 'healthy progress on stderr'; return '{}' }
        'daemon-fail' { $global:LASTEXITCODE=1; Write-Error 'Cannot connect to the Docker daemon'; return }
        'throw' { $global:LASTEXITCODE=0; throw 'launch failed with stale zero exit code' }
        default { $global:LASTEXITCODE=1; Write-Error "Error response from daemon: get $($call[-1]): no such volume"; return }
    }
}
foreach ($name in @('aetheris-forensic_minio_data', 'aetheris-forensic_ollama_data',
    'aetheris-forensic_huggingface_cache', 'aetheris-mobile-android_android_hf_cache',
    'aetheris-mobile-ios_ios_hf_cache')) {
    $script:mode='missing'
    Assert-True (-not (Test-DockerVolumeExists -Docker MockDocker -Name $name)) "Missing legacy volume is optional: $name"
    Assert-True ($ErrorActionPreference -eq 'Stop') 'Probe restores Stop preference'
}
$script:mode='present'
Assert-True (Test-DockerVolumeExists -Docker MockDocker -Name existing) 'Existing volume recognized'
$script:calls.Clear()
Ensure-DockerVolume -Docker MockDocker -Name existing
Assert-True ($script:calls.Count -eq 1) 'Existing persistent volume is not recreated'
foreach ($name in @('aetheris-forensic_pgdata','aetheris-forensic_pgadmin_data')) {
    $script:mode='missing';$script:calls.Clear()
    Ensure-DockerVolume -Docker MockDocker -Name $name
    Assert-True ($script:calls.Count -eq 2 -and $script:calls[1][1] -eq 'create') "Missing persistent volume is created: $name"
}
$script:mode='daemon-fail';$script:calls.Clear();$failed=$false
try { Ensure-DockerVolume -Docker MockDocker -Name unavailable } catch {
    $failed = $_.Exception.Message -match 'Cannot connect'
}
Assert-True $failed 'Docker daemon failure is propagated'
Assert-True ($script:calls.Count -eq 1) 'Daemon failure never triggers volume creation'
$script:mode='create-fail';$failed=$false
try { Ensure-DockerVolume -Docker MockDocker -Name denied } catch {
    $failed = $_.Exception.Message -match 'permission denied'
}
Assert-True $failed 'Failed volume creation is propagated'
$script:mode='healthy-stderr'
Assert-True (Test-DockerVolumeExists -Docker MockDocker -Name healthy) 'Successful stderr does not abort'
$script:mode='throw'
$result = Invoke-NativeCapture -Exe MockDocker -Arguments @('volume','inspect','throw')
Assert-True ($result.ExitCode -ne 0 -and $result.Text -match 'launch failed') 'Terminating invocation cannot reuse stale success'
Assert-True ($ErrorActionPreference -eq 'Stop') 'Invocation failure restores Stop preference'
Write-Host "PASS: $script:checks volume-probe checks with simulated Windows PowerShell error records."
