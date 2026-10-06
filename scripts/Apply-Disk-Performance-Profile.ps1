param([string]$EnvFile = ".env")
if (-not (Test-Path $EnvFile)) { New-Item -ItemType File -Path $EnvFile | Out-Null }

function Set-EnvValue([string]$Key, [string]$Value) {
  $lines = @(Get-Content $EnvFile -ErrorAction SilentlyContinue)
  $found = $false
  $out = foreach ($line in $lines) {
    if ($line -match "^$([regex]::Escape($Key))=") { $found = $true; "$Key=$Value" } else { $line }
  }
  if (-not $found) { $out += "$Key=$Value" }
  Set-Content -Path $EnvFile -Value $out -Encoding UTF8
}

Set-EnvValue EXTRACT_MODE full
Set-EnvValue EXTRACT_MAX_FILE_BYTES 0
Set-EnvValue EXTRACT_SKIP_SYSTEM_PATHS false
Set-EnvValue EXTRACT_SOURCE_PROFILE auto
Set-EnvValue EXTRACT_SOURCE_BENCHMARK_MB 64
Set-EnvValue EXTRACT_HDD_READERS 1
Set-EnvValue EXTRACT_HDD_MAX_READERS 2
Set-EnvValue EXTRACT_HDD_SHARDS 8
Set-EnvValue EXTRACT_HDD_CHUNK_MB 8
Set-EnvValue EXTRACT_HDD_DEFER_PHASE3 true
Set-EnvValue MAX_CONCURRENT_DISK_BUILDS 1
Set-EnvValue EXTRACT_ZSTD_LEVEL 1
Set-EnvValue EXTRACT_SHARD_COUNT 8
Set-EnvValue EXTRACT_TAR_BUFSIZE 1048576
Set-EnvValue EXTRACT_SCRATCH_DIR /scratch
Set-EnvValue PHASE3_STREAM_RAG_DURING_EXTRACT false
Write-Host "Applied disk performance profile to $EnvFile"
