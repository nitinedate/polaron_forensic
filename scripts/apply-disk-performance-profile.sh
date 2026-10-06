#!/usr/bin/env bash
set -euo pipefail

ENV_FILE="${1:-.env}"
if [ ! -f "$ENV_FILE" ]; then
  touch "$ENV_FILE"
fi

set_env() {
  key="$1"; value="$2"
  if grep -q "^${key}=" "$ENV_FILE"; then
    sed -i "s|^${key}=.*|${key}=${value}|" "$ENV_FILE"
  else
    printf '%s=%s\n' "$key" "$value" >> "$ENV_FILE"
  fi
}

# Evidence completeness: do not gain speed by excluding large files.
set_env EXTRACT_MODE full
set_env EXTRACT_MAX_FILE_BYTES 0
set_env EXTRACT_SKIP_SYSTEM_PATHS false

# Auto-detect HDD/SSD/NVMe. HDD uses sequential/locality scheduling.
set_env EXTRACT_SOURCE_PROFILE auto
set_env EXTRACT_SOURCE_BENCHMARK_MB 64
set_env EXTRACT_HDD_READERS 1
set_env EXTRACT_HDD_MAX_READERS 2
set_env EXTRACT_HDD_SHARDS 8
set_env EXTRACT_HDD_CHUNK_MB 8
set_env EXTRACT_HDD_DEFER_PHASE3 true

# Keep one large disk extraction per physical I/O lane.
set_env MAX_CONCURRENT_DISK_BUILDS 1

# Compression is deliberately cheap; evidence bytes remain lossless.
set_env EXTRACT_ZSTD_LEVEL 1
set_env EXTRACT_SHARD_COUNT 8
set_env EXTRACT_TAR_BUFSIZE 1048576

# Put this on SSD/NVMe when available. Change if your fast scratch mount differs.
set_env EXTRACT_SCRATCH_DIR /scratch

# RAG GPU is already kept out of source extraction on HDD by the effective planner.
set_env PHASE3_STREAM_RAG_DURING_EXTRACT false

printf 'Applied disk performance profile to %s\n' "$ENV_FILE"
printf 'For best HDD performance, mount a separate SSD/NVMe at /scratch when available.\n'
