# iOS lockdown / advanced-logical collection on the examiner Windows host.
param(
    [Parameter(Mandatory = $true)][string]$PayloadFile,
    [Parameter(Mandatory = $true)][string]$ResultFile
)

$ErrorActionPreference = "Continue"
$here = Split-Path -Parent $MyInvocation.MyCommand.Path
$repoRoot = Split-Path -Parent $here
$acquirePath = Join-Path $here "host-mobile-acquire.ps1"
try {
    if (Test-Path -LiteralPath $acquirePath) { . $acquirePath }
} catch {
    $loadErr = $_.Exception.Message
    try {
        $loadErr | Set-Content -LiteralPath $ResultFile -Encoding UTF8
    } catch {}
    throw
}

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
if (-not $label) { $label = "iPhone" }
$stamp = Get-Date -Format "yyyyMMdd_HHmmss"
$methodTag = "ADVANCED_LOGICAL"
$override = ([string]$p.method_override).ToLowerInvariant()
if ($override -match "backup") { $methodTag = "BACKUP" }
elseif ($override -match "logical" -and $override -notmatch "advanced") { $methodTag = "LOGICAL" }
# Full File System needs a jailbreak. Live USB collection stays Advanced Logical.
$runName = ($caseId + "_" + $ev + "_" + $label + "_" + $methodTag + "_" + $stamp)
$caseDir = Join-Path $caseRoot $caseId
# Always create the complete forensic case skeleton, even when some folders are empty.
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
New-Item -ItemType Directory -Force -Path $original, $working, $logs, $exportsEarly, $reports, $hashesEarly, $review | Out-Null
$logPath = Join-Path $logs "ios_acquire.log"
if (-not $progress) { $progress = Join-Path $logs "progress.json" }

$methodDecision = @{
    selected         = "advanced_logical"
    considered       = @("backup", "advanced_logical", "logical")
    rejected         = @{}
    rationale        = "iOS Agent owns this collection: iTunes-style backup (advanced logical) plus AFC/shared media when the phone is unlocked and trusts this PC."
    deeper_available = @("full_file_system")
    owner_agent      = "iosagent"
}

Write-Prog @{
    stage      = "acquire"
    item       = "ios_backup"
    bytes_done = 0
    files_seen = 0
    run_name   = $runName
    detail     = "Starting iPhone backup on this PC. Keep the phone unlocked and Trust This Computer."
    category   = "Collecting"
}

$copied = 0
$err = ""
$ok = $false
$backupPath = ""
$backupComplete = $false
$bytes = [int64]0
$fileN = 0
$afcFiles = 0
$afcBytes = [int64]0
$afcSucceeded = $false
try {
if (Get-Command Invoke-IosToolAcquire -ErrorAction SilentlyContinue) {
    $maxBackupTries = 4
    for ($tryN = 1; $tryN -le $maxBackupTries; $tryN++) {
        if ($progress -and (Test-Path -LiteralPath ($progress + ".cancel"))) {
            $err = "cancelled"
            $ok = $false
            break
        }
        $ios = Invoke-IosToolAcquire -OutDir $original -LogPath $logPath -Udid ([string]$p.device_id) `
            -ProgressFile $progress -RunName $runName -Stamp $stamp
        if ($ios.ok) {
            $backupPath = [string]$ios.backup_path
            $backupComplete = $false
            if ($backupPath -and (Get-Command Test-IosBackupComplete -ErrorAction SilentlyContinue)) {
                $backupComplete = Test-IosBackupComplete -Path $backupPath
            } elseif ($backupPath -and (Test-Path -LiteralPath $backupPath)) {
                $backupComplete = @(Get-ChildItem -LiteralPath $backupPath -Recurse -File -Filter "Manifest.*" -ErrorAction SilentlyContinue |
                    Where-Object { $_.Length -ge 64 }).Count -gt 0
            }
            if ($backupComplete) {
                $ok = $true
                $copied = [int]($ios.files_copied)
                if ($ios.bytes) { $bytes = [int64]$ios.bytes }
                $err = ""
                break
            }
            $err = "ios_backup_incomplete_no_manifest_usb_may_have_dropped"
            if (Get-Command Write-AcquireLog -ErrorAction SilentlyContinue) {
                Write-AcquireLog $logPath "Backup helper returned ok but Manifest.db/plist is missing - collection is not complete."
            }
        } else {
            $err = [string]($ios.error)
            $detail = [string]($ios.detail)
            if ($err -match 'not_enough_disk|NotEnoughDiskSpace' -or $detail -match 'NotEnoughDiskSpace|not_enough_disk') {
                $err = "ios_backup_not_enough_disk_space"
            }
            if (-not $err) { $err = "ios_backup_incomplete_no_manifest_usb_may_have_dropped" }
        }
        if ($err -match 'not_enough_disk|device_locked|pair_|cancelled') { break }
        if ($tryN -lt $maxBackupTries) {
            Write-Prog @{
                stage        = "acquire"
                item         = "ios_backup"
                bytes_done   = $bytes
                files_seen   = $copied
                run_name     = $runName
                progress_pct = 6
                detail       = "USB backup dropped before Manifest.db. Keep the iPhone unlocked - resuming attempt $($tryN + 1) of $maxBackupTries into the same staging folder."
                category     = "Collecting"
            }
            if (Get-Command Write-AcquireLog -ErrorAction SilentlyContinue) {
                Write-AcquireLog $logPath ("iOS backup incomplete ({0}); retrying {1}/{2}" -f $err, ($tryN + 1), $maxBackupTries)
            }
            Start-Sleep -Seconds 10
        }
    }
} else {
    $err = "iOS acquire helper missing"
}

# Do not fall back to Explorer MTP CopyHere. iPhone "Internal Storage" under This PC
# blocks inside COM with 0 files (this hung the previous collection for 45+ minutes).
# Photos and app data come from usbmux backup, then AFC + house_arrest (iosagent only).
if (Get-Command Write-AcquireLog -ErrorAction SilentlyContinue) {
    Write-AcquireLog $logPath "Skipping iPhone MTP Internal Storage copy (CopyHere hangs). Using lockdown backup plus AFC/house_arrest."
}

$runAfc = $true
if ($err -match 'ios_backup_not_enough_disk_space|not_enough_disk|NotEnoughDiskSpace') {
    $runAfc = $false
    if (Get-Command Write-AcquireLog -ErrorAction SilentlyContinue) {
        Write-AcquireLog $logPath "Skipping AFC/house_arrest because storage preflight says the complete iOS collection cannot fit. Free/select storage first, then retry once."
    }
}

if ($runAfc -and (Get-Command Invoke-IosAfcAcquire -ErrorAction SilentlyContinue)) {
    Write-Prog @{
        stage         = "acquire"
        item          = "afc_media"
        bytes_done    = $bytes
        files_seen    = $copied
        run_name      = $runName
        progress_pct  = $(if ($ok) { 68 } else { 8 })
        detail        = $(if ($ok) {
            'iTunes backup finished ({0} GB). Now pulling shared photos and WhatsApp container - next step, not a new collection.' -f [math]::Round($bytes/1GB, 2)
        } else {
            "Pulling iPhone shared media and WhatsApp container. Keep the phone unlocked."
        })
        category      = "Collecting"
    }
    try {
        $afc = Invoke-IosAfcAcquire -OutDir $original -LogPath $logPath -Udid ([string]$p.device_id) `
            -ProgressFile $progress -Stamp $stamp -BackupBytes $bytes -BackupFiles $copied
        if ($afc -and $afc.ok) { $afcSucceeded = $true }
        if ($afc -and $afc.files) {
            $afcFiles = [int]$afc.files
            $afcBytes = [int64]$afc.bytes
            $copied = [Math]::Max($copied, $afcFiles)
        }
    } catch {
        $afcSucceeded = $false
        if (Get-Command Write-AcquireLog -ErrorAction SilentlyContinue) {
            Write-AcquireLog $logPath ("iOS AFC/house_arrest failed (backup is still kept): {0}" -f $_.Exception.Message)
        }
    }
}

if ((Get-Command Invoke-IosReadableArtifacts -ErrorAction SilentlyContinue) -and (
        $ok -or $backupComplete -or $afcFiles -gt 0 -or (
            $backupPath -and (Get-Command Test-IosBackupComplete -ErrorAction SilentlyContinue) -and (Test-IosBackupComplete -Path $backupPath)
        )
    )) {
    try {
        # Second readable copy goes to 03_Working_Copy/<run> (derived overlay). 05_Exports/<run>
        # must contain only <run>.zip/.ufd/.pas/.ufdx; the ZIP carries readable_artifacts inside.
        $null = Invoke-IosReadableArtifacts -Original $original -Exports $working -LogPath $logPath
    } catch {
        if (Get-Command Write-AcquireLog -ErrorAction SilentlyContinue) {
            Write-AcquireLog $logPath ("iOS readable materialise failed (hashed backup is still kept): {0}" -f $_.Exception.Message)
        }
    }
}

$backupBytes = $bytes
$backupFiles = $copied
$bytes = [int64]0
$fileN = 0
$countRoot = $original
if (Get-Command Get-DirFileStats -ErrorAction SilentlyContinue) {
    $stats = Get-DirFileStats -Dir $countRoot
    $fileN = [int]$stats.files
    $bytes = [int64]$stats.bytes
} else {
    Get-ChildItem -LiteralPath $countRoot -Recurse -File -ErrorAction SilentlyContinue | ForEach-Object {
        $bytes += $_.Length
        $fileN++
    }
}
$bytes = [Math]::Max([int64]$bytes, [int64]$backupBytes + [int64]$afcBytes)
$fileN = [Math]::Max($fileN, $backupFiles + $afcFiles)
if ($fileN -gt 0) { $copied = [Math]::Max($copied, $fileN) }
if ($ok) { $copied = [Math]::Max($copied, $fileN) }
elseif ($fileN -gt 0 -and -not $err) { $err = "ios_backup_incomplete_no_manifest_usb_may_have_dropped" }
if ($err -match 'no_manifest|incomplete' -and ($afcFiles -gt 0) -and $err -notmatch 'not_enough_disk') {
    if ($ios -and ([string]$ios.detail -match 'NotEnoughDiskSpace|not_enough_disk')) {
        $err = "ios_backup_not_enough_disk_space"
    }
}
} catch {
    $ok = $false
    if (-not $err) { $err = [string]$_.Exception.Message }
    if (Get-Command Write-AcquireLog -ErrorAction SilentlyContinue) {
        Write-AcquireLog $logPath ("iOS acquire crashed: {0}" -f $_.Exception.Message)
    }
}
$exports = Join-Path (Join-Path $caseDir "05_Exports") $runName
$hashes = Join-Path (Join-Path $caseDir "08_Hashes") $runName
$inventory = @{}
$exportPkg = @{ packages = @{} }
$backupIsComplete = $false
if ($backupPath -and (Get-Command Test-IosBackupComplete -ErrorAction SilentlyContinue)) {
    try { $backupIsComplete = [bool](Test-IosBackupComplete -Path $backupPath) } catch { }
}
if (-not $backupIsComplete) { $backupIsComplete = [bool]$backupComplete }

# Never label a media-only/partial collection as a complete evidence ZIP.  The
# previous condition ($ok -or $afcFiles -gt 0) tried to ZIP AFC data even when
# the iTunes backup had failed, which produced the confusing double error seen
# by the examiner.
if ($ok -and $backupIsComplete -and (Get-Command Invoke-HostExportPackages -ErrorAction SilentlyContinue)) {
    $pack = Invoke-HostExportPackages -Original $original -Exports $exports -Logs $logs `
        -Hashes $hashes -CaseId $caseId -EvidenceId $ev -Method "advanced_logical" `
        -ProgressFile $progress -LogPath $logPath
    if ($pack.ok) {
        if ($pack.inventory) { $inventory = $pack.inventory }
        if ($pack.export) { $exportPkg = $pack.export }
    } else {
        $ok = $false
        $exportErr = $(if ($pack.error) { "full_evidence_zip_failed: " + [string]$pack.error } else { "full_evidence_zip_failed" })
        if (-not $err) { $err = $exportErr }
        if (Get-Command Write-AcquireLog -ErrorAction SilentlyContinue) {
            Write-AcquireLog $logPath $exportErr
        }
    }
} elseif (-not $backupIsComplete -and $afcFiles -gt 0) {
    New-Item -ItemType Directory -Force -Path $logs | Out-Null
    $partial = @{
        complete = $false
        reason = $(if ($err) { $err } else { "ios_backup_incomplete" })
        afc_files = $afcFiles
        afc_bytes = $afcBytes
        original = $original
        note = "AFC/WhatsApp shared data is preserved, but no complete evidence ZIP is created until the iTunes-style backup completes."
    }
    $partial | ConvertTo-Json -Depth 6 | Set-Content -LiteralPath (Join-Path $logs "PARTIAL_COLLECTION.json") -Encoding UTF8
    if (Get-Command Write-AcquireLog -ErrorAction SilentlyContinue) {
        Write-AcquireLog $logPath "Full ZIP intentionally skipped because the iTunes-style backup is incomplete; partial AFC data remains preserved."
    }
}
$errList = New-Object System.Collections.Generic.List[string]
if (-not $ok -and $err) { $errList.Add([string]$err) | Out-Null }
if (-not $ok -and $afcFiles -gt 0) {
    $errList.Add(("ios_afc_collected_but_itunes_backup_incomplete files={0} bytes={1}" -f $afcFiles, $afcBytes)) | Out-Null
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
        working   = $working
        logs      = $logs
        exports   = $exports
        hashes    = $hashes
        reports   = $reports
        review    = $review
    }
    device             = @{ os_family = "ios"; model = [string]$p.device_label; serial = [string]$p.device_id }
    limitations        = @(
        "iOS keychain/keystore is not available without a backup password or full-filesystem method."
        "Advanced Logical is an iTunes-style backup plus AFC/house_arrest. It is not a full filesystem image. iCloud Photos (Optimize iPhone Storage) and apps excluded from backup stay on Apple servers and will not match Settings > About storage."
        "WhatsApp chats are in the backup as hashed files (ChatStorage.sqlite). iosagent unpacks them into readable_artifacts/whatsapp after the backup."
    )
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
$finalStage = "failed"
$finalDetail = [string]$err
$finalError = [string]$err
if ($ok) {
    $finalStage = "complete"
    $finalDetail = "Collection finished"
    $finalError = ""
}
Write-Prog @{
    stage      = $finalStage
    item       = "complete"
    bytes_done = $bytes
    files_seen = $copied
    run_name   = $runName
    detail     = $finalDetail
    category   = $(if ($ok) { "Complete" } else { "Failed" })
}
$res = @{
    ok                 = $ok
    run_name           = $runName
    stage_reached      = $finalStage
    error              = $finalError
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
