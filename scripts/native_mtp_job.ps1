# STA MTP collection job started by the host drive helper (Android file-transfer).
param(
    [Parameter(Mandatory = $true)][string]$PayloadFile,
    [Parameter(Mandatory = $true)][string]$ResultFile
)

$ErrorActionPreference = "Continue"
$here = Split-Path -Parent $MyInvocation.MyCommand.Path
$repoRoot = Split-Path -Parent $here
$acquirePath = Join-Path $here "host-mobile-acquire.ps1"
$copyPath = Join-Path $here "mtp_logical_copy.ps1"
if (Test-Path -LiteralPath $acquirePath) { . $acquirePath }

$p = Get-Content -LiteralPath $PayloadFile -Raw -Encoding UTF8 | ConvertFrom-Json
$progress = [string]$p.progress_file
if (-not $progress) {
    $progress = ([string]$ResultFile) -replace "acq_result_", "acq_progress_"
}

function Write-Prog($obj) {
    if (-not $progress) { return }
    try { ($obj | ConvertTo-Json -Compress -Depth 6) | Set-Content -LiteralPath $progress -Encoding UTF8 } catch {}
}
function Write-Res($obj) {
    try { ($obj | ConvertTo-Json -Compress -Depth 12) | Set-Content -LiteralPath $ResultFile -Encoding UTF8 } catch {}
}

$caseRoot = [string]$p.case_root
if ($caseRoot -match '^[\\/]evidence([\\/]|$)') {
    $rel = ($caseRoot -replace '^[\\/]evidence[\\/]?', '' -replace '/', '\')
    $caseRoot = if ($rel) { Join-Path (Join-Path $repoRoot "evidence") $rel } else { Join-Path $repoRoot "evidence\cases" }
} elseif (-not $caseRoot -or $caseRoot -eq "/evidence/cases" -or $caseRoot -eq "\evidence\cases") {
    $caseRoot = Join-Path $repoRoot "evidence\cases"
}

$caseId = ([string]$p.case_id) -replace '[^\w\-.]', '_'
if (-not $caseId) { $caseId = "CASE-UNKNOWN" }
$ev = ([string]$p.evidence_id) -replace '[^\w\-.]', '_'
if (-not $ev) { $ev = "E00" }
$label = ([string]($p.device_label)) -replace '[^\w\-.]', '_'
if (-not $label) { $label = "ANDROID" }
$stamp = Get-Date -Format "yyyyMMdd_HHmmss"
$override = ([string]$p.method_override).ToLowerInvariant()
$methodTag = "FILESYSTEM"
if ($override -eq "full_file_system") { $methodTag = "FFS" }
elseif ($override -eq "logical") { $methodTag = "LOGICAL" }
elseif ($override -eq "backup") { $methodTag = "BACKUP" }
elseif ($override -match "advanced") { $methodTag = "ADVANCED_LOGICAL" }
$wantedMethod = $(if ($override) { $override } else { "full_file_system" })
$runName = ($caseId + "_" + $ev + "_" + $label + "_" + $methodTag + "_" + $stamp)
$caseDir = Join-Path $caseRoot $caseId
$caseFolders = @(
    "01_Authority", "02_Original_Extraction", "03_Working_Copy", "04_PA_Case",
    "05_Exports", "06_Reports", "07_Logs", "08_Hashes", "09_Review", "10_Disclosure"
)
foreach ($folder in $caseFolders) { New-Item -ItemType Directory -Force -Path (Join-Path $caseDir $folder) | Out-Null }
$original = Join-Path (Join-Path $caseDir "02_Original_Extraction") $runName
$working = Join-Path (Join-Path $caseDir "03_Working_Copy") $runName
$logs = Join-Path (Join-Path $caseDir "07_Logs") $runName
$exportsEarly = Join-Path (Join-Path $caseDir "05_Exports") $runName
$reports = Join-Path (Join-Path $caseDir "06_Reports") $runName
$hashesEarly = Join-Path (Join-Path $caseDir "08_Hashes") $runName
$review = Join-Path (Join-Path $caseDir "09_Review") $runName
$media = Join-Path $original "mtp_shared"
New-Item -ItemType Directory -Force -Path $media, $working, $logs, $exportsEarly, $reports, $hashesEarly, $review | Out-Null
$logPath = Join-Path $logs "mtp_copy.log"
if (-not $progress) {
    $progress = Join-Path $logs "progress.json"
}

$methodDecision = @{
    selected         = "file_system"
    considered       = @("logical", "advanced_logical", "backup", "file_system", "full_file_system")
    rejected         = @{}
    rationale        = "Android Agent owns this collection: accessible filesystem over ADB (tar of shared storage, avoiding Windows MAX_PATH), plus full-file-system attempt via adb root/su if already present. No lock bypass."
    deeper_available = @("physical")
    owner_agent      = "androidagent"
}

$adb = $null
$copied = 0
$err = ""

function Invoke-JobAdb {
    param([string]$Detail)
    if (-not (Get-Command Invoke-AndroidAdbAcquire -ErrorAction SilentlyContinue)) { return $null }
    Write-Prog @{
        stage      = "acquire"
        item       = "adb_logical"
        bytes_done = $copied
        files_seen = $copied
        run_name   = $runName
        detail     = $Detail
        category   = "Collecting"
    }
    $adbOut = Join-Path $original "adb_logical"
    New-Item -ItemType Directory -Force -Path $adbOut | Out-Null
    return Invoke-AndroidAdbAcquire -OutDir $adbOut -LogPath $logPath -ProgressFile $progress -WantedMethod $wantedMethod
}

trap {
    $msg = [string]$_.Exception.Message
    if ($msg -match '(?i)not enough space|disk full|space on the disk') {
        $msg = "The evidence drive is full, so collection stopped. Free space on that drive, or choose a case folder on a drive with room, then retry. Files already copied are kept."
    }
    $fail = @{
        ok                 = $false
        run_name           = $runName
        stage_reached      = "failed"
        error              = $msg
        errors             = @($msg)
        method_decision    = $methodDecision
        limitations        = @($msg)
        paths              = @{ case_root = $caseDir; run_name = $runName; original = $original; logs = $logs }
        acquisition_record = @{ output_size = 0; file_count = [int]$copied; missing_fields = @() }
        evidence_package   = @{ run_name = $runName; extraction_data = @(); complete = $false; file_count = [int]$copied }
        verification       = @{ ok = $false; verified = 0 }
    }
    try { Write-Res $fail } catch {}
    break
}

# ADB first. MTP CopyHere of "Phone" can hang in Explorer and would otherwise
# block this entire job with 0 files.
$adb = Invoke-JobAdb "Authorising ADB and collecting the accessible Android filesystem"
if ($adb -and $adb.ok -and $adb.files_copied) { $copied = $copied + [int]$adb.files_copied }
elseif ($adb -and -not $adb.ok -and $adb.error) { $err = [string]$adb.error }

# Staging survives case-folder wipes (junctions / Explorer CopyHere).
# Copy it back before MTP so WhatsApp/DCIM are never missing from the sealed run.
$restored = 0
if (Get-Command Restore-AdbStageIntoCase -ErrorAction SilentlyContinue) {
    $restored = Restore-AdbStageIntoCase -Original $original -LogPath $logPath -ProgressFile $progress
    if ($restored -gt $copied) { $copied = $restored }
}

Write-Prog @{
    stage      = "acquire"
    item       = "mtp_shared"
    bytes_done = $copied
    files_seen = $copied
    run_name   = $runName
    detail     = "Copying shared storage from the phone"
    category   = "Collecting"
}

# MTP only fills gaps. Never CopyHere WhatsApp if ADB already landed that tree —
# Explorer CopyHere hangs for tens of minutes at a few hundred files.
$waAdb = Join-Path $original "adb_logical\filesystem\sdcard\sdcard_Android_media_com.whatsapp"
$waAdbLegacy = Join-Path $original "adb_logical\filesystem\sdcard\sdcard_WhatsApp"
$stageRoot = if (Get-Command Get-AdbStageRoot -ErrorAction SilentlyContinue) { Get-AdbStageRoot } else { Join-Path $repoRoot "ap" }
$waStage = Join-Path $stageRoot "sdcard_Android_media_com.whatsapp"
$waStageLegacy = Join-Path $stageRoot "sdcard_WhatsApp"
if ((Test-Path -LiteralPath $waAdb) -or (Test-Path -LiteralPath $waAdbLegacy) -or (Test-Path -LiteralPath $waStage) -or (Test-Path -LiteralPath $waStageLegacy)) {
    $env:AETHERIS_SKIP_MTP_WHATSAPP = "1"
    Write-AcquireLog $logPath "ADB already copied WhatsApp into staging/case. MTP will skip Android/media CopyHere."
}
if (Get-Command Copy-MtpDeviceLogical -ErrorAction SilentlyContinue) {
    Write-Prog @{
        stage      = "acquire"
        item       = "mtp_shared"
        bytes_done = $copied
        files_seen = $copied
        run_name   = $runName
        detail     = "Copying shared storage visible under This PC"
        category   = "Collecting"
    }
    $mtp = Copy-MtpDeviceLogical -DeviceName ([string]$p.device_label) -InstanceId ([string]$p.device_id) `
        -DestDir $media -LogPath $logPath -OsHint "android" -ProgressFile $progress `
        -AdbFilesCopied $copied -AdbBytesCopied 0
    $copied = $copied + [int]$mtp.files_copied
    if (-not $mtp.ok -and -not $copied) { $err = [string]$mtp.error }
} elseif (Test-Path -LiteralPath $copyPath) {
    $raw = & powershell.exe -STA -NoProfile -ExecutionPolicy Bypass -File $copyPath `
        -InstanceId ([string]$p.device_id) -DeviceName ([string]$p.device_label) `
        -DestDir $media -LogPath $logPath -OsHint android 2>&1 | Out-String
    $line = ($raw -split '[\r\n]+' | Where-Object { $_.Trim().StartsWith('{') } | Select-Object -Last 1)
    if ($line) {
        $obj = $line | ConvertFrom-Json
        $copied = $copied + [int]($obj.files_copied)
        if (-not $obj.ok -and -not $copied) { $err = [string]$obj.error }
    } elseif (-not $raw) { $err = "MTP copy produced no output" } else { $err = $raw }
} else {
    if (-not $copied) { $err = "MTP copy script missing" }
}

# USB debugging often enumerates only after File transfer/MTP is up.
if ((-not $adb -or $adb.adb_state -ne "device") -and (Get-Command Invoke-AndroidAdbAcquire -ErrorAction SilentlyContinue)) {
    $retry = Invoke-JobAdb "Retrying ADB after MTP/file-transfer came online"
    if ($retry) {
        $adb = $retry
        if ($retry.ok -and $retry.files_copied) { $copied = $copied + [int]$retry.files_copied }
        if ($retry.ok) { $err = "" }
        elseif ($retry.error) { $err = [string]$retry.error }
    }
}

$bytes = [int64]0
$fileN = 0
$treeStats = Get-DirFileStats -Dir $original
if ($treeStats) {
    $fileN = [int]$treeStats.files
    $bytes = [int64]$treeStats.bytes
}
$copied = [Math]::Max($copied, $fileN)
$ok = ($copied -gt 0 -or $bytes -gt 0)
$exports = Join-Path (Join-Path $caseDir "05_Exports") $runName
$hashes = Join-Path (Join-Path $caseDir "08_Hashes") $runName
$inventory = @{}
$exportPkg = @{ packages = @{} }
if ($ok -and (Get-Command Invoke-AndroidReadableArtifacts -ErrorAction SilentlyContinue)) {
    try {
        # Derived copy lives in 03_Working_Copy/<run>; 05_Exports/<run> is packages only.
        $null = Invoke-AndroidReadableArtifacts -Original $original -Exports $working -LogPath $logPath
    } catch {
        if (Get-Command Write-AcquireLog -ErrorAction SilentlyContinue) {
            Write-AcquireLog $logPath ("Android readable materialise failed (pulled files are still kept): {0}" -f $_.Exception.Message)
        }
    }
}
if ($ok -and (Get-Command Invoke-HostExportPackages -ErrorAction SilentlyContinue)) {
    $exportMethod = "file_system"
    if ($adb -and $adb.app_private) { $exportMethod = "full_file_system" }
    elseif ($adb -and -not $adb.shared_complete) { $exportMethod = "logical" }
    $pack = Invoke-HostExportPackages -Original $original -Exports $exports -Logs $logs `
        -Hashes $hashes -CaseId $caseId -EvidenceId $ev -Method $exportMethod `
        -ProgressFile $progress -LogPath $logPath
    if ($pack.ok) {
        if ($pack.inventory) { $inventory = $pack.inventory }
        if ($pack.export) { $exportPkg = $pack.export }
    } else {
        $ok = $false
        $err = $(if ($pack.error) { "full_evidence_zip_failed: " + [string]$pack.error } else { "full_evidence_zip_failed" })
        if (Get-Command Write-AcquireLog -ErrorAction SilentlyContinue) {
            Write-AcquireLog $logPath $err
        }
    }
}
$errList = New-Object System.Collections.Generic.List[string]
if (-not $ok -and $err) { $errList.Add([string]$err) | Out-Null }
if ($adb -and $adb.ok) {
    if ($adb.app_private) {
        $methodDecision.selected = "full_file_system"
        $methodDecision.rationale = "Android USB: full file system archived (root/su or app-private databases obtained)."
        $methodDecision.deeper_available = @("physical")
    } elseif ($adb.shared_complete) {
        $methodDecision.selected = "file_system"
        $methodDecision.rationale = "Android USB: accessible filesystem over ADB pull of shared storage (Android/media, DCIM, Pictures). /data/data was not readable on this production build."
        $methodDecision.deeper_available = @("full_file_system", "physical")
    } else {
        $methodDecision.selected = $(if ($adb.sms_ok) { "advanced_logical" } else { "logical" })
        $methodDecision.rationale = "Android USB: ADB logical/backup plus MTP shared-storage copy."
        $methodDecision.deeper_available = @("file_system", "full_file_system")
    }
}
$limitations = New-Object System.Collections.Generic.List[string]
if ($adb -and $adb.disk_note) { [void]$limitations.Add([string]$adb.disk_note) }
$hasPlainMsgstore = Test-Path -LiteralPath (Join-Path $original "adb_logical\app_data")
$hasWaMedia = [bool](Test-Path -LiteralPath $waAdb)
$hasCrypt = $false
if ($hasWaMedia) {
    $waDb = Join-Path $waAdb "Databases"
    if (-not (Test-Path -LiteralPath $waDb)) { $waDb = $waAdb }
    $enumDb = Get-Win32LongPath -Path $waDb
    try {
        foreach ($f in [System.IO.Directory]::EnumerateFiles($enumDb, "*", [System.IO.SearchOption]::AllDirectories)) {
            if ($f -match '(?i)crypt1[245]|msgstore\.db\.crypt') { $hasCrypt = $true; break }
        }
    } catch {
        $hasCrypt = $hasWaMedia
    }
}
$hasSmsProv = Test-Path -LiteralPath (Join-Path $original "adb_logical\providers\sms.txt")
if ($hasSmsProv) {
    $smsLen = 0
    try { $smsLen = (Get-Item -LiteralPath (Join-Path $original "adb_logical\providers\sms.txt")).Length } catch {}
    if ($smsLen -lt 40) { $hasSmsProv = $false }
}
if ($adb -and $adb.app_private -or $hasPlainMsgstore) {
    # App-private data landed.
} else {
    if (-not $hasWaMedia) {
        [void]$limitations.Add("WhatsApp media/databases were not present in this package. Keep the phone unlocked and re-run; ADB will wait up to 10 minutes for the first WhatsApp file (large trees list slowly).")
    } elseif ($hasCrypt) {
        [void]$limitations.Add("WhatsApp media and encrypted local backups (crypt12/14/15) were collected. Plaintext chats (msgstore.db under /data/data) need an already-rooted phone or a successful on-phone Back up my data prompt. No lock bypass is used.")
    } else {
        [void]$limitations.Add("WhatsApp media was collected. Plaintext chat databases were not. Production WhatsApp blocks adb backup and run-as; /data/data needs an already-rooted phone.")
    }
    if ($hasSmsProv) {
        [void]$limitations.Add("SMS/MMS/contacts/calendar were collected via content providers.")
    }
}
$summary = @{
    ok                 = $ok
    run_name           = $runName
    file_count         = $copied
    total_bytes        = $bytes
    method_decision    = $methodDecision
    paths              = @{
        case_root = $caseDir
        run_name  = $runName
        original  = $original
        logs      = $logs
        exports   = $exports
        hashes    = $hashes
    }
    device             = @{ os_family = "android"; model = [string]$p.device_label; serial = [string]$p.device_id }
    limitations        = @($limitations)
    errors             = @($errList)
    content_inventory  = $inventory
    export_packages    = $exportPkg
    verification       = @{ ok = $ok; verified = $(if ($ok) { $copied } else { 0 }) }
    acquisition_record = @{ output_size = $bytes; file_count = $copied; missing_fields = @() }
    evidence_package   = @{
        run_name             = $runName
        extraction_data      = @()
        file_count           = $copied
        complete             = $ok
        collection_summary   = (Join-Path $logs "collection_summary.json")
        content_inventory    = $inventory
        export_packages      = $exportPkg
    }
}
$summaryJson = if (Get-Command Convert-AcquireResultToJson -ErrorAction SilentlyContinue) {
    Convert-AcquireResultToJson -Obj $summary
} else { $summary | ConvertTo-Json -Compress -Depth 12 }
$summaryJson | Set-Content -LiteralPath (Join-Path $logs "collection_summary.json") -Encoding UTF8
Write-Prog @{
    stage      = $(if ($ok) { "complete" } else { "failed" })
    item       = "complete"
    bytes_done = $bytes
    files_seen = $copied
    run_name   = $runName
    detail     = $(if ($ok) { "Collection finished" } else { $err })
    category   = $(if ($ok) { "Complete" } else { "Failed" })
}
$res = @{
    ok                 = $ok
    run_name           = $runName
    stage_reached      = $(if ($ok) { "complete" } else { "failed" })
    error              = $(if ($ok) { "" } else { $err })
    errors             = @($errList)
    paths              = $summary.paths
    limitations        = $summary.limitations
    method_decision    = $methodDecision
    evidence_package   = $summary.evidence_package
    acquisition_record = $summary.acquisition_record
    content_inventory  = $inventory
    export_packages    = $exportPkg
    verification       = $summary.verification
}
$resJson = if (Get-Command Convert-AcquireResultToJson -ErrorAction SilentlyContinue) {
    Convert-AcquireResultToJson -Obj $res
} else { $res | ConvertTo-Json -Compress -Depth 12 }
$resJson | Set-Content -LiteralPath $ResultFile -Encoding UTF8
if (-not $ok) { exit 1 }
exit 0
