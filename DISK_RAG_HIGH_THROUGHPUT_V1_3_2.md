# Polaron Disk + RAG High-Throughput Architecture v1.3.2

## Goal

This release optimizes the forensic Disk pipeline for a practical service-level objective (SLO):

- **50 GB evidence image:** forensic/artifact-ready in **< 30 minutes** when the source path can sustain the required I/O.
- **500 GB evidence image:** forensic/artifact-ready in **< 3 hours** when the source path can sustain the required I/O.
- Preserve the original source as immutable evidence, preserve a complete filesystem inventory, retain per-materialized-file hashes, and do not trade correctness for speed.
- Keep GPU OCR/vector enrichment asynchronous so extraction is never blocked waiting for an LLM/embedding model.

The raw minimum throughput implied by these targets is about **28 MB/s** for 50 GB/30 min and **46 MB/s** for 500 GB/3 h. Real deployments need margin for filesystem enumeration, E01 decompression, output compression, storage upload, database writes and parsing. A healthy local SATA HDD can often sustain > 80 MB/s sequential reads, but a fragmented/failing disk, USB 2.0 bridge, slow NAS, heavily compressed E01, very high file counts, encrypted containers, or an overloaded host can make the SLO physically impossible. The code now minimizes avoidable passes so the bottleneck is much closer to the actual source/storage limit.

## What changed

### 1. HDD-aware source I/O planner

`backend/app/services/disk_io_profile.py` detects rotational vs SSD/NVMe media on Linux from `/sys/dev/block/.../queue/rotational` when visible. `DISK_SOURCE_MEDIA=hdd|ssd|nvme|auto` is available for Docker/VM/Windows-host cases where the physical device is hidden.

For **HDD**, E01/raw extraction uses **one sequential source reader** and several contiguous/path-range output shards. Multiple readers on a rotational image cause seek thrashing and can be slower than one reader. SSD/NVMe can still use multiple independent readers.

### 2. Large files stream directly into tar/zstd

Large evidence files no longer need to be materialized as one giant Python `bytes` object before being packed. `iter_file_from_disk()` feeds tar/zstd in 4 MiB chunks once a file exceeds `EXTRACT_STREAM_THRESHOLD_BYTES` (8 MiB by default).

When file hashing is enabled, SHA-256 is calculated in that same read pass. There is no second evidence read just to hash the file.

If a streamed read fails **after** a tar member has started, the entire shard fails and is retried from the immutable source/checkpoint. The code does not continue with a possibly corrupt tar stream.

### 3. Required complete evidence inventory

Every enumerated filesystem entry is written to:

`jobs/<job_id>/extracted-disk/full-inventory.jsonl.zst`

This ledger is intentionally broader than the optimized materialized artifact set. It records the existence/metadata of files that policy chooses not to duplicate, so optimization cannot make those entries disappear from the case record. `DISK_FULL_INVENTORY_REQUIRED=true` makes failure to persist this ledger a hard error rather than a warning.

The final manifest now contains:

- `inventory_files_total`
- `inventory_bytes_total`
- `full_inventory_uri`
- `source_io_profile`
- `evidence_coverage.source_preserved`
- `evidence_coverage.full_inventory_persisted`
- materialized, filtered and unreadable counts

### 4. Metadata ledgers use bounded RAM

Extract-node lists, full inventory, shard indexes and the final combined index are serialized as streamed JSONL + zstd instead of building very large joined byte strings in memory. Loading these ledgers also uses streamed zstd readers.

This is important on 500 GB+ images with hundreds of thousands or millions of filesystem entries.

### 5. Parse each tar.zst shard once

Previously `artifact_parse.py` grouped by `(part_uri, read_budget)`. If one shard contained SQLite, browser, text and metadata-only artifacts, the same 5–13 GB compressed shard could be decompressed once for every budget class.

`iter_files_from_part_budgets()` now performs one MinIO/local -> zstd -> tar pass for all requested files in a shard while applying a different byte limit to each file.

This removes one of the largest avoidable HDD/local-object-store penalties.

### 6. RAG raw fallback is one pass per shard

Previously `dual_rag_index.chunk_rows_for_embedding()` could call `read_file_from_part()` once for each fallback file. Because tar is sequential, every call restarted decompression at byte zero.

Fallback requests are now grouped by `part_uri`; each part is streamed once for the whole batch. The legacy RAG reader also changed from `get_bytes(whole_part) -> decompress(whole_part)` to constant-memory streamed zstd/tar iteration.

### 7. Local object-store fallback no longer reads whole shards into RAM

`storage.put_file()` now uses filesystem streaming/copy rather than `file_path.read_bytes()` for potentially multi-gigabyte shard files.

### 8. RAG/OCR remain off the extraction critical path

The existing Phase-3 architecture is retained: extraction/materialization/parsing can progress as shards complete, while GPU RAG/OCR are queued separately. The disk worker does not wait for embeddings to finish before it can release the source I/O path.

For the SLO profile, `PHASE3_STREAM_OCR_DURING_EXTRACT=false` by default so OCR cannot steal CPU/GPU/thermal headroom from the source-critical stage. RAG is also not run inline during extraction.

## Default SLO configuration

The complete project ships with these baseline defaults:

```env
EXTRACT_MODE=defensible
EXTRACT_DISK_WORKERS=8
EXTRACT_SHARD_COUNT=12
EXTRACT_UPLOAD_CONCURRENCY=8
EXTRACT_ZSTD_LEVEL=1
EXTRACT_TAR_BUFSIZE=2097152
EXTRACT_STREAM_THRESHOLD_BYTES=8388608
EXTRACT_STREAM_CHUNK_BYTES=4194304
EXTRACT_HASH_FILES=true
DISK_FULL_INVENTORY_ENABLED=true
DISK_FULL_INVENTORY_REQUIRED=true
DISK_SOURCE_MEDIA=auto
MAX_CONCURRENT_DISK_BUILDS=1

PARSE_WORKERS=8
PARSE_PARALLEL_BUCKETS=4
PARSE_DB_COMMIT_BATCH=250
PARSE_DRAIN_BATCH_LIMIT=1200
PARSE_DRAIN_MAX_ROUNDS=25

PHASE3_STREAM_DURING_EXTRACT=true
PHASE3_STREAM_RAG_DURING_EXTRACT=false
PHASE3_STREAM_OCR_DURING_EXTRACT=false
```

`MAX_CONCURRENT_DISK_BUILDS=1` is deliberate for the latency/SLO profile. Two cases reading from the same HDD at the same time can destroy sequential throughput. Raise it only when source images are on independent physical devices and PostgreSQL/MinIO have enough capacity.

## Evidence integrity model

Performance does **not** mean modifying or deleting the original evidence.

1. Original E01/raw/folder evidence remains read-only/source-preserved.
2. Every filesystem entry is recorded in the required compressed full inventory.
3. Selected/materialized evidence is hashed in the same streaming pass.
4. Read failures are visible as unreadable counts/logs.
5. A partial streamed tar member never silently continues; its shard fails and is retried.
6. Checkpoints keep completed shards resumable.
7. Filtering statistics are written into the final manifest.
8. RAG/AI output is derived enrichment; it is not the source of truth for artifact existence.

`defensible` mode is used because duplicating every low-value system binary from a 500 GB image is not necessary to make forensic artifacts searchable and would make a fixed time SLO impossible on many systems. The complete inventory + immutable original source preserve the evidence universe. If a case requires a byte-for-byte materialization of every file, use `EXTRACT_MODE=full`; that mode should not be held to the same 30-minute/3-hour SLO.

## HDD operating profile

For an external/server HDD:

1. Keep the evidence image on the attached HDD; do not copy it to the application first.
2. Set `DISK_SOURCE_MEDIA=hdd` if Docker/VM auto-detection reports `unknown`.
3. Keep only one active disk build on that physical drive.
4. Put Docker data/MinIO/PostgreSQL/temp files on SSD/NVMe, not on the evidence HDD.
5. Use USB 3.x/SATA, not USB 2.0.
6. Avoid antivirus/indexer processes scanning the evidence/output directories during the benchmark.

The code will use one image reader for HDD and multiple contiguous shards. Sequential source I/O is more important than reader count on rotational media.

## SSD/NVMe operating profile

With local NVMe, the planner can use several independent EWF/TSK readers, bounded by live CPU/thermal/resource-governor state. The adaptive semaphore can reduce concurrency if the machine becomes hot or another case is active.

## Recommended benchmark acceptance test

Always benchmark the same evidence and same extraction policy before/after.

### 50 GB gate

- source: 50 GB representative E01/raw image
- target: < 30 minutes to artifact-ready baseline
- required average source-equivalent rate: ~28 MB/s minimum
- zero missing known artifacts compared with the reference run
- `full_inventory_persisted=true`
- materialized file hashes present when `EXTRACT_HASH_FILES=true`
- no corrupt shard/retry loop
- no PostgreSQL pool timeout/OOM

### 500 GB gate

- source: 500 GB representative image
- target: < 3 hours to artifact-ready baseline
- required average source-equivalent rate: ~46 MB/s minimum
- same evidence/inventory/parity checks as above

For an apples-to-apples validation, record:

- media (`hdd`, `ssd`, `nvme`)
- interface (USB 3.x/SATA/NVMe/NAS)
- E01 compression level/segment count
- image logical/physical size
- total files enumerated
- total bytes materialized
- extraction wall time
- parsing wall time
- RAG baseline wall time
- unreadable count
- filtered count by policy
- known artifact counts before vs after

## Test cases included

`backend/tests/test_disk_high_throughput_v132.py` adds checks for:

- HDD = one sequential source reader
- deterministic `DISK_SOURCE_MEDIA` override
- per-path read budgets sharing a single tar.zst pass
- RAG fallbacks from the same shard sharing a single stream pass

The source also passes Python syntax/compile validation and Docker Compose YAML validation in the build workspace. Full pytest execution requires the project's runtime dependencies (`zstandard`, `psycopg2-binary`, etc.) and should be run in the built backend container.

## Production verification commands

```bash
# Build the exact runtime dependencies first
docker compose build --no-cache api worker-disk worker-parse rag-gpu

docker compose run --rm api \
  pytest -q \
    tests/test_disk_high_throughput_v132.py \
    tests/test_extract_parallel_plan.py \
    tests/test_dual_rag_chunk.py

# Start stack
docker compose up -d
```

For an external HDD hidden behind Docker Desktop/VM virtualization, set in `.env`:

```env
DISK_SOURCE_MEDIA=hdd
```

Then restart the disk worker.

## Files changed for v1.3.2

Core changes are in:

- `backend/app/config.py`
- `backend/app/services/disk_io_profile.py`
- `backend/app/services/extracted_disk.py`
- `backend/app/services/disk_manifest.py`
- `backend/app/services/storage.py`
- `backend/app/services/tar_cache.py`
- `backend/app/services/artifact_parse.py`
- `backend/app/services/dual_rag_index.py`
- `backend/app/services/rag_index.py`
- `backend/tests/test_disk_high_throughput_v132.py`
- `docker-compose.yml`
- `.env.example`

