# V45.3 - Stage evidence (E01/EWF segments, DD, mobile dumps) into the docker-desktop VM.
#
#   .\scripts\stage-evidence.ps1 -Source "G:\Image of Reception Laptop" -CaseName reception-laptop
#
# Why: the forensic workers read evidence through Docker Desktop's Windows
# file-sharing layer when it sits on G:\ / F:\ bind mounts. That layer tops out
# at a few MB/s under parallel seeks (the 2 h 15 m / 50 GB extraction) and a
# worker blocked inside it is in an uninterruptible kernel state - the source of
#   "cannot stop container ... tried to kill container, but did not receive an exit event".
# Staging copies the files ONCE, sequentially (what the sharing layer is good
# at), into a named volume that is native ext4 inside the VM. Extraction then
# reads at NVMe speed and the container always stops cleanly.
#
# The volume is mounted in api / worker-disk / worker-parse as /host/<letter>
# (default z) so it shows in the UI as drive Z: - register evidence from there
# exactly as from any other drive. Nothing in the workflow changes.
param(
    [Parameter(Mandatory = $true)][string]$Source,
    [Parameter(Mandatory = $true)][string]$CaseName,
    [string]$Letter = $(if ($env:EVIDENCE_STAGING_LETTER) { $env:EVIDENCE_STAGING_LETTER } else { "z" }),
    [string]$ProjectName = "aetheris-forensic",
    [switch]$Verify,
    [switch]$Remove
)

$ErrorActionPreference = "Stop"
$Letter = $Letter.ToLower()
if ($Letter.Length -ne 1 -or $Letter -notmatch "^[a-z]$") { throw "Letter must be a single a-z character" }
if (Get-PSDrive -Name $Letter.ToUpper() -ErrorAction SilentlyContinue) {
    throw "Drive $($Letter.ToUpper()): exists on this Windows host. Pick an unused letter: set EVIDENCE_STAGING_LETTER in .env and re-run start_docker."
}
$case = ($CaseName -replace "[^A-Za-z0-9._-]", "_")
$volume = "${ProjectName}_evidence_staging"

if ($Remove) {
    Write-Host "Removing staged case '$case' from volume $volume ..."
    docker run --rm -v "${volume}:/dst" alpine:3.20 sh -c "rm -rf '/dst/$case' && ls -la /dst"
    exit $LASTEXITCODE
}

if (-not (Test-Path -LiteralPath $Source)) { throw "Source not found: $Source" }
$src = (Resolve-Path -LiteralPath $Source).Path
$items = Get-ChildItem -LiteralPath $src -File
$bytes = ($items | Measure-Object -Property Length -Sum).Sum
Write-Host ("Staging {0} file(s), {1:N1} GB from '{2}' -> volume {3} as '{4}'" -f $items.Count, ($bytes / 1GB), $src, $volume, $case)

# One sequential stream per file; cp -p keeps mtimes. The shell script is written
# to a temp file and bind-mounted (never passed as a quoted argument - Windows
# PowerShell 5.1 mangles embedded double quotes in native-command arguments).
$shell = @"
set -e
mkdir -p "/dst/$case"
for f in /src/*; do
  n=`$(basename "`$f")
  if [ -f "/dst/$case/`$n" ] && [ "`$(stat -c %s "`$f")" = "`$(stat -c %s "/dst/$case/`$n")" ]; then
    echo "skip (same size): `$n"; continue
  fi
  start=`$(date +%s)
  cp -p "`$f" "/dst/$case/`$n.part" && mv "/dst/$case/`$n.part" "/dst/$case/`$n"
  sz=`$(stat -c %s "/dst/$case/`$n"); end=`$(date +%s); d=`$((end-start)); [ "`$d" -gt 0 ] || d=1
  echo "copied `$n `$((sz/1048576)) MiB in `${d}s (`$((sz/1048576/d)) MiB/s)"
done
touch /dst/.evidence-staging
df -h /dst | tail -1
"@
$tmp = Join-Path ([System.IO.Path]::GetTempPath()) ("aetheris-stage-" + [guid]::NewGuid().ToString("N") + ".sh")
# LF line endings and no BOM - this file is executed by /bin/sh inside the container.
[System.IO.File]::WriteAllText($tmp, ($shell -replace "`r`n", "`n"), (New-Object System.Text.UTF8Encoding($false)))
try {
    $prevEap = $ErrorActionPreference
    $ErrorActionPreference = "Continue"
    & docker run --rm -v "${volume}:/dst" -v "${src}:/src:ro" -v "${tmp}:/stage.sh:ro" alpine:3.20 sh /stage.sh
    $code = $LASTEXITCODE
    $ErrorActionPreference = $prevEap
}
finally {
    Remove-Item -LiteralPath $tmp -Force -ErrorAction SilentlyContinue
}
if ($code -ne 0) { throw "staging copy failed (exit $code)" }

if ($Verify) {
    Write-Host "Verifying SHA-256 (source vs staged)..."
    foreach ($it in $items) {
        $h1 = (Get-FileHash -LiteralPath $it.FullName -Algorithm SHA256).Hash.ToLower()
        $h2 = (docker run --rm -v "${volume}:/dst" alpine:3.20 sha256sum "/dst/$case/$($it.Name)").Split(" ")[0]
        if ($h1 -ne $h2) { throw "HASH MISMATCH: $($it.Name)" }
        Write-Host "  ok $($it.Name) $h1"
    }
}

Write-Host ""
Write-Host "Staged. In the Polaron UI register evidence from drive $($Letter.ToUpper()): -> \$case\ (container path /host/$Letter/$case)." -ForegroundColor Green
Write-Host "Set DISK_SOURCE_MEDIA=nvme in .env so the extractor uses the parallel-reader profile for staged evidence."
