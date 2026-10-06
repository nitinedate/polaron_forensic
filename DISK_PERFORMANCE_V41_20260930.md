# Disk Performance V41 — HDD/SSD/NVMe forensic extraction

## Objective
Make server-side E01/RAW disk extraction source-aware and substantially faster without reducing forensic evidence coverage.

## Main changes
- Automatic source classification: HDD / SSD / NVMe / network / unknown.
- HDD uses 1 sequential reader by default (hard maximum 2) plus inode/locality ordered shards.
- HDD reads use larger 8 MiB logical chunks.
- SSD/NVMe retain parallel E01 readers.
- HDD defers streamed Phase-3 parse/OCR/RAG until evidence extraction is complete, preventing random source contention.
- Whole evidence files are no longer loaded into Python RAM before TAR/Zstd packing; file bytes are streamed once while optional SHA-256 is calculated in the same pass.
- Rare files with unknown census size are spooled to scratch instead of being represented as empty.
- Temporary compressed shards use configurable `EXTRACT_SCRATCH_DIR`; point this at SSD/NVMe when the source is HDD.
- Default extraction profile is `full` with `EXTRACT_MAX_FILE_BYTES=0`; large files are not removed to gain speed.
- One large disk build per physical I/O lane by default.
- Completed extraction is explicitly logged/displayed as **Evidence Ready** while OCR/RAG enrichment can continue afterward.

## Recommended HDD profile
```env
EXTRACT_MODE=full
EXTRACT_MAX_FILE_BYTES=0
EXTRACT_SOURCE_PROFILE=auto
EXTRACT_HDD_READERS=1
EXTRACT_HDD_MAX_READERS=2
EXTRACT_HDD_SHARDS=8
EXTRACT_HDD_CHUNK_MB=8
EXTRACT_HDD_DEFER_PHASE3=true
MAX_CONCURRENT_DISK_BUILDS=1
EXTRACT_ZSTD_LEVEL=1
EXTRACT_SCRATCH_DIR=/scratch
PHASE3_STREAM_RAG_DURING_EXTRACT=false
```

If the source is definitely a rotational HDD and auto-detection is unavailable inside Docker, set `EXTRACT_SOURCE_PROFILE=hdd`.

## Performance SLA guidance
The software target for Evidence Ready is 50 GB <= 30 min and 500 GB <= 3 h when the physical source can sustain the required read rate and the image/file count is not pathological. A 500 GB source below roughly 46 MB/s cannot physically satisfy a 3-hour full-read target.

Deep unallocated-space carving, exhaustive OCR, and final AI/RAG enrichment are tracked independently and must not block Evidence Ready.
