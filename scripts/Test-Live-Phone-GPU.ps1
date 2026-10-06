[CmdletBinding()]
param(
    [ValidateSet('forensic', 'mobile-android', 'mobile-ios', 'mobile-extract')]
    [string]$Product = 'mobile-android',
    [string]$ProjectName = '',
    [string]$DeviceSerial = '',
    [string]$EvidencePath = '',
    [string[]]$KeyFiles = @(),
    [string]$PythonPath = '',
    [string]$AdbPath = '',
    [string]$OutputDirectory = '',
    [ValidateRange(30, 1800)][int]$GpuTimeoutSeconds = 600,
    [ValidateRange(60, 7200)][int]$PhoneTimeoutSeconds = 3600
)

$ErrorActionPreference = 'Stop'
$RepoRoot = Split-Path -Parent (Split-Path -Parent $MyInvocation.MyCommand.Path)
. (Join-Path $RepoRoot 'scripts\host-mobile-acquire.ps1')
if (-not $ProjectName) { $ProjectName = 'aetheris-' + $Product }
if (-not $OutputDirectory) {
    $OutputDirectory = Join-Path (Get-MobileAcquisitionRoot) ('live-verification-' + [guid]::NewGuid().ToString('N'))
}
if (Test-Path -LiteralPath $OutputDirectory) { throw 'Use a new output directory; existing evidence is never overwritten.' }
New-Item -ItemType Directory -Path $OutputDirectory -Force | Out-Null
$OutputDirectory = (Resolve-Path -LiteralPath $OutputDirectory).Path
$DiagnosticDirectory = Join-Path $OutputDirectory 'diagnostics'
New-Item -ItemType Directory -Path $DiagnosticDirectory | Out-Null
$CheckScript = Join-Path $RepoRoot 'scripts\verify-live-phone-gpu.py'
$script:Checks = @()

function Add-Check([string]$Name, [string]$Status, [string]$Detail) {
    $script:Checks += [pscustomobject]@{ name = $Name; status = $Status; detail = $Detail; required = $true }
    Write-Host ("[{0}] {1}: {2}" -f $Status.ToUpperInvariant(), $Name, $Detail)
}

function Quote-NativeArgument([string]$Value) {
    $quoted = [regex]::Replace($Value, '(\\*)"', '$1$1\"')
    $quoted = [regex]::Replace($quoted, '(\\+)$', '$1$1')
    return '"' + $quoted + '"'
}

function Invoke-BoundedNative([string]$Executable, [string[]]$Arguments, [int]$Seconds = 60, [string]$Label = '') {
    $start = New-Object System.Diagnostics.ProcessStartInfo
    $start.FileName = $Executable
    $start.Arguments = (($Arguments | ForEach-Object { Quote-NativeArgument ([string]$_) }) -join ' ')
    $start.WorkingDirectory = $RepoRoot
    $start.UseShellExecute = $false
    $start.CreateNoWindow = $true
    $start.RedirectStandardOutput = $true
    $start.RedirectStandardError = $true
    $nativeProcess = New-Object System.Diagnostics.Process
    $nativeProcess.StartInfo = $start
    try {
        if (-not $nativeProcess.Start()) { throw 'Cannot start the verification command.' }
        $standardOutput = $nativeProcess.StandardOutput.ReadToEndAsync()
        $standardError = $nativeProcess.StandardError.ReadToEndAsync()
        $watch = [System.Diagnostics.Stopwatch]::StartNew()
        $nextUpdate = 15
        while (-not $nativeProcess.WaitForExit(1000)) {
            if ($watch.Elapsed.TotalSeconds -ge $Seconds) {
                $nativeProcess.Kill()
                $nativeProcess.WaitForExit()
                throw 'Verification command reached its execution deadline.'
            }
            if ($Label -and $watch.Elapsed.TotalSeconds -ge $nextUpdate) {
                Write-Host ("{0} running ({1}s)" -f $Label, [int]$watch.Elapsed.TotalSeconds)
                $nextUpdate += 15
            }
        }
        $nativeProcess.WaitForExit()
        return [pscustomobject]@{ Code = $nativeProcess.ExitCode; Out = $standardOutput.Result; Error = $standardError.Result }
    } finally {
        $nativeProcess.Dispose()
    }
}

function Import-StageReport([string]$Name, [string]$Path) {
    if (-not (Test-Path -LiteralPath $Path)) { Add-Check $Name 'blocked' 'No completed acceptance result was produced.'; return }
    try {
        $record = Get-Content -LiteralPath $Path -Raw | ConvertFrom-Json
        if ($record.status -notin @('passed', 'blocked', 'failed') -or -not $record.checks) { throw 'Invalid acceptance result.' }
        $required = @($record.checks | Where-Object { $_.required -eq $true })
        if ($record.status -eq 'passed' -and ($required.Count -eq 0 -or @($required | Where-Object { $_.status -ne 'pass' }).Count)) {
            throw 'A pass must have completed every required check.'
        }
        $status = 'blocked'
        if ($record.status -eq 'passed') { $status = 'pass' }
        if ($record.status -eq 'failed') { $status = 'fail' }
        Add-Check $Name $status ('Detailed checks saved to ' + (Split-Path -Leaf $Path))
    } catch { Add-Check $Name 'blocked' 'The acceptance result could not be read.' }
}

try {
    if (-not $PythonPath) { $PythonPath = Find-KitPython }
    if (-not $AdbPath) {
        $AdbPath = Find-HostTool -Names @('adb.exe', 'adb') -ExtraPaths @(
            (Join-Path $RepoRoot 'tools\platform-tools\adb.exe'),
            (Join-Path $env:LOCALAPPDATA 'Android\Sdk\platform-tools\adb.exe'),
            'C:\platform-tools\adb.exe'
        )
    }
    if (-not $PythonPath) { throw 'No working host Python was found.' }
    $version = Invoke-BoundedNative $PythonPath @('-c', 'import sys; print("%d.%d" % sys.version_info[:2])') 15
    if ($version.Code -ne 0 -or [version]$version.Out.Trim() -lt [version]'3.11') { throw 'Python 3.11 or newer is required.' }
    $phone = Join-Path $DiagnosticDirectory 'phone.json'
    $phoneArguments = @($CheckScript, '--mode', 'phone', '--output', $phone, '--adb', $(if ($AdbPath) { $AdbPath } else { 'adb' }))
    if ($DeviceSerial) { $phoneArguments += @('--serial', $DeviceSerial) }
    if ($EvidencePath) { $phoneArguments += @('--source', (Resolve-Path -LiteralPath $EvidencePath).Path) }
    foreach ($key in $KeyFiles) { $phoneArguments += @('--key', (Resolve-Path -LiteralPath $key).Path) }
    # Make the source package available to the host kit without installing GPU libraries on Windows.
    $oldPythonPath = $env:PYTHONPATH
    try {
        $env:PYTHONPATH = Get-KitPythonPathEnv
        $phoneResult = Invoke-BoundedNative $PythonPath $phoneArguments $PhoneTimeoutSeconds 'Phone collection'
    } finally { $env:PYTHONPATH = $oldPythonPath }
    Import-StageReport 'live_phone' $phone
    $acquired = Join-Path $DiagnosticDirectory 'acquired-files.json'
    if (Test-Path -LiteralPath $acquired) {
        Write-Host 'Selected evidence is retained locally; key and chat bytes are excluded from diagnostics.'
    }
} catch { Add-Check 'live_phone' 'blocked' 'Host Python/ADB or phone collection could not finish; check the connected phone and local tools.' }

$apiContainer = ''
$gpuContainer = ''
$containerRoot = '/tmp/aetheris-live-' + [guid]::NewGuid().ToString('N')
$dockerCommand = Get-Command docker -ErrorAction SilentlyContinue
if ($dockerCommand) {
    try {
        $gpuService = 'worker-ocr'
        if ($Product -in @('forensic', 'mobile-extract')) { $gpuService = 'worker-ocr-gpu' }
        $api = Invoke-BoundedNative $dockerCommand.Source @('ps', '--filter', ('label=com.docker.compose.project=' + $ProjectName), '--filter', 'label=com.docker.compose.service=api', '--format', '{{.ID}}') 30
        $gpu = Invoke-BoundedNative $dockerCommand.Source @('ps', '--filter', ('label=com.docker.compose.project=' + $ProjectName), '--filter', ('label=com.docker.compose.service=' + $gpuService), '--format', '{{.ID}}') 30
        $apiIds = @($api.Out -split '\r?\n' | Where-Object { $_.Trim() })
        $gpuIds = @($gpu.Out -split '\r?\n' | Where-Object { $_.Trim() })
        if ($api.Code -ne 0 -or $apiIds.Count -ne 1) { throw 'One running product API container is required.' }
        $apiContainer = $apiIds[0].Trim()
        if ($gpu.Code -ne 0 -or $gpuIds.Count -ne 1) { throw 'One running product OCR/GPU worker is required.' }
        $gpuContainer = $gpuIds[0].Trim()
    } catch { Add-Check 'docker_runtime' 'blocked' 'The selected product API/GPU worker could not be resolved; check -Product and -ProjectName.' }
} else { Add-Check 'docker_runtime' 'blocked' 'Docker is unavailable on this host.' }

if ($apiContainer) {
    try {
        $raw = Join-Path $DiagnosticDirectory 'raw'
        if (-not (Test-Path -LiteralPath $raw)) { throw 'No collected or supplied WhatsApp input directory exists.' }
        $mkdir = Invoke-BoundedNative $dockerCommand.Source @('exec', $apiContainer, 'mkdir', '-m', '700', $containerRoot) 30
        if ($mkdir.Code -ne 0) { throw 'Cannot create a private derived workspace.' }
        $transfer = Invoke-BoundedNative $dockerCommand.Source @('cp', $raw, ($apiContainer + ':' + $containerRoot + '/raw')) $PhoneTimeoutSeconds 'Evidence staging'
        if ($transfer.Code -ne 0) { throw 'Cannot stage selected evidence in the API container.' }
        $crypto = Invoke-BoundedNative $dockerCommand.Source @('exec', $apiContainer, 'python', '/scripts/verify-live-phone-gpu.py', '--mode', 'whatsapp', '--timeout', [string]$PhoneTimeoutSeconds, '--source', ($containerRoot + '/raw'), '--derived', ($containerRoot + '/derived'), '--output', ($containerRoot + '/whatsapp.json')) ($PhoneTimeoutSeconds + 60) 'WhatsApp authentication and parsing'
        $copyResult = Invoke-BoundedNative $dockerCommand.Source @('cp', ($apiContainer + ':' + $containerRoot + '/whatsapp.json'), (Join-Path $DiagnosticDirectory 'whatsapp.json')) 30
        Import-StageReport 'whatsapp_data' (Join-Path $DiagnosticDirectory 'whatsapp.json')
        # Successful derived databases stay local for ingestion through the existing UI.
        $derivedCopy = Invoke-BoundedNative $dockerCommand.Source @('cp', ($apiContainer + ':' + $containerRoot + '/derived'), (Join-Path $OutputDirectory 'derived')) $PhoneTimeoutSeconds
        $whatsReport = Get-Content -LiteralPath (Join-Path $DiagnosticDirectory 'whatsapp.json') -Raw | ConvertFrom-Json
        $backupCheck = $whatsReport.checks | Where-Object { $_.name -eq 'backup_authentication' } | Select-Object -First 1
        if ($whatsReport.status -eq 'passed' -and $backupCheck.evidence.encrypted_backups -gt 0 -and $derivedCopy.Code -ne 0) {
            Add-Check 'derived_evidence_copy' 'blocked' 'Backups authenticated but derived databases could not be retained on the host.'
        }
    } catch { Add-Check 'whatsapp_data' 'blocked' 'Authenticated decryption/message verification could not finish; no keyless success is claimed.' }
}
if ($gpuContainer) {
    try {
        $gpuPath = $containerRoot + '-gpu.json'
        $inference = Invoke-BoundedNative $dockerCommand.Source @('exec', $gpuContainer, 'python', '/scripts/verify-live-phone-gpu.py', '--mode', 'gpu', '--timeout', [string]$GpuTimeoutSeconds, '--output', $gpuPath) ($GpuTimeoutSeconds + 60) 'CUDA, OCR and vision checks'
        $gpuCopy = Invoke-BoundedNative $dockerCommand.Source @('cp', ($gpuContainer + ':' + $gpuPath), (Join-Path $DiagnosticDirectory 'gpu.json')) 30
        Import-StageReport 'gpu_inference' (Join-Path $DiagnosticDirectory 'gpu.json')
        $gpuCleanup = Invoke-BoundedNative $dockerCommand.Source @('exec', $gpuContainer, 'rm', '-f', $gpuPath) 30
    } catch { Add-Check 'gpu_inference' 'blocked' 'Real GPU verification could not finish; no CPU or simulated pass is accepted.' }
}
if ($apiContainer) {
    try { $cleanup = Invoke-BoundedNative $dockerCommand.Source @('exec', $apiContainer, 'rm', '-rf', $containerRoot) 30 }
    catch { Add-Check 'container_cleanup' 'blocked' 'Temporary container evidence could not be removed; retained local evidence is available.' }
}

foreach ($required in @('live_phone', 'whatsapp_data', 'gpu_inference')) {
    if (-not @($script:Checks | Where-Object { $_.name -eq $required }).Count) { Add-Check $required 'blocked' 'This required live check did not execute.' }
}
$overall = 'passed'
if (@($script:Checks | Where-Object { $_.status -ne 'pass' }).Count) { $overall = 'blocked' }
if (@($script:Checks | Where-Object { $_.status -eq 'fail' }).Count) { $overall = 'failed' }
$summary = [pscustomobject]@{
    status = $overall
    product = $Product
    project = $ProjectName
    live_verification_complete = ($overall -eq 'passed')
    checks = $script:Checks
    case_ingestion_and_report_verification = 'not_run; ingest selected evidence and verify the case in the application'
    raw_evidence_in_diagnostics = $false
}
$summary | ConvertTo-Json -Depth 12 | Set-Content -LiteralPath (Join-Path $DiagnosticDirectory 'summary.json') -Encoding UTF8
$lines = @('# Live phone/GPU verification', '', ('Result: ' + $overall), '')
foreach ($item in $script:Checks) { $lines += ('- ' + $item.name + ': ' + $item.status + ' - ' + $item.detail) }
$lines += @('', 'Raw evidence and derived databases remain local. They are not included in this diagnostic ZIP.', 'Case ingestion and report verification are separate checks in the application.')
$lines | Set-Content -LiteralPath (Join-Path $DiagnosticDirectory 'RESULTS.md') -Encoding UTF8
$zip = Join-Path $OutputDirectory 'LIVE-VERIFICATION-RESULTS.zip'
# Explicit inclusion prevents acquired keys/databases under diagnostics/raw from being uploaded.
$diagnosticFiles = @('phone.json', 'whatsapp.json', 'gpu.json', 'acquired-files.json', 'summary.json', 'RESULTS.md') | ForEach-Object {
    $candidate = Join-Path $DiagnosticDirectory $_
    if (Test-Path -LiteralPath $candidate) { $candidate }
}
Compress-Archive -LiteralPath $diagnosticFiles -DestinationPath $zip -CompressionLevel Optimal
Write-Host ('Verification result: ' + $overall)
Write-Host ('Diagnostic ZIP: ' + $zip)
Write-Host ('Acquired/derived evidence: ' + $OutputDirectory)
if ($overall -ne 'passed') { exit 2 }
exit 0
