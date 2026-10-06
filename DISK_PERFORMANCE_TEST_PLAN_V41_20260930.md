# Disk Performance V41 Test Plan

## TC-DISK-001 — HDD source detection
1. Attach a known rotational HDD containing a forensic image.
2. Start extraction with `EXTRACT_SOURCE_PROFILE=auto`.
3. Verify extraction log contains `source=hdd` and `reason=hdd_sequential_locality`.
4. Verify `parallel_readers=1` by default.
Expected: HDD is detected and random-reader fan-out is not used.

## TC-DISK-002 — Forced HDD fallback
Set `EXTRACT_SOURCE_PROFILE=hdd` and start the same case.
Expected: planner uses HDD mode even when `/sys` device metadata is unavailable in Docker.

## TC-DISK-003 — SSD/NVMe path
Run the same image from SSD/NVMe.
Expected: source is `ssd` or `nvme`; planner is permitted multiple E01 readers according to host capacity.

## TC-DISK-004 — 50 GB Evidence Ready target
Use a 50 GB representative forensic image on a healthy HDD.
Record source MB/s, files enumerated/extracted, elapsed extraction time, skipped/unreadable count.
Acceptance target: Evidence Ready <= 30 minutes when source throughput supports it.

## TC-DISK-005 — 500 GB Evidence Ready target
Use a 500 GB representative image.
Acceptance target: Evidence Ready <= 3 hours when sustained physical source read rate is >= ~46 MB/s and storage is healthy.

## TC-DISK-006 — Artifact/evidence parity
Run the same image on old and V41 builds. Compare counts and identities for registry, EVTX, browser, email, chat, documents, media, LNK, Jump Lists, Prefetch, recycle bin, cloud artifacts, deleted metadata, and carved evidence.
Expected: no evidence loss caused by the performance profile. Any difference must be explained.

## TC-DISK-007 — Large-file preservation
Include files >100 MB and >2 GB in the image.
Expected: `full` mode keeps them in the extraction/index; no generic size cap excludes them.

## TC-DISK-008 — Memory behavior
Include a multi-GB file.
Expected: extraction worker RSS does not increase by the full file size because TAR packing streams the file rather than calling `read_full_file_from_disk`.

## TC-DISK-009 — HDD Phase-3 isolation
During HDD extraction monitor parse/OCR/RAG queues.
Expected: streamed Phase 3 does not compete with source HDD extraction. After Evidence Ready, follow-up parse/OCR/RAG begins/continues normally.

## TC-DISK-010 — Scratch-device optimization
Mount SSD/NVMe at `/scratch` while source remains HDD.
Expected: compressed shard staging and MinIO upload do not cause extra random I/O on the source HDD.

## TC-DISK-011 — Stop/resume
Stop a large HDD extraction after several shards, then resume.
Expected: completed shards remain checkpointed; resume preserves source profile and does not duplicate/drop evidence.

## TC-DISK-012 — Unreadable sector/file behavior
Use an image containing intentionally unreadable/corrupt entries.
Expected: errors are logged explicitly; no silent corruption; a short read aborts/retries the affected shard rather than publishing a malformed evidence shard.

## Automated tests
Inside the backend container/environment where project requirements are installed:
```bash
pytest -q tests/test_source_media.py tests/test_disk_performance_v41.py tests/test_extract_parallel_plan.py tests/test_extract_stream_reader.py
```
