# Disk Source Residency and Full-Intake Gate V27 — 2026-09-24

## Requirement

Disk-image evidence must follow a strict source-residency rule.

### 1. Server / server-network / removable media

When an image set is visible to the forensic server on an attached SSD, HDD, USB/pen drive, mounted network drive/share, or other server-accessible path:

- select it through **Server / network / removable drives**;
- register the existing path only;
- do **not** browser-upload the image;
- do **not** create a second server staging copy;
- do **not** mirror disk-image segments to MinIO/object storage;
- extract/read the E01/EWF/RAW segments directly from that mounted source;
- mark the source as `intake=server_local`, `source_residency=server_local`;
- use `cleanup_policy=never_delete_source`.

The Enterprise Console now exposes server drives through the forensic server API even when the browser is connected over the LAN or by DNS/IP. Localhost/HostDrive-helper detection is no longer required to browse server-side media.

### 2. Client/browser evidence

When the image physically exists on a separate client computer and the server cannot access that path directly:

1. The browser declares the complete file count before transferring the first byte.
2. The Download Agent opens a **fail-closed intake gate**.
3. At most **5 files are uploaded concurrently**.
4. Every file is first written to a hidden `.uploading-<uuid>` temporary name.
5. The temporary file is flushed/fsynced and atomically renamed to its final segment name only after the entire file is present.
6. Partial files therefore cannot be counted, registered, or opened by extraction.
7. The server checks both the database received counter and the actual staged-file count.
8. The intake state moves `receiving -> verifying -> complete`.
9. Segment registration/listing happens while the state is `verifying`, so all downstream work remains blocked.
10. The pipeline is released only after the complete declared set has been registered successfully.

Disk-image uploads are staged once under `DATA_ROOT/uploads/<job-id>/intake`; they are not duplicated into object storage before extraction.

## Global pipeline hold

For a `browser_upload` job, any state other than explicit `complete` is treated as incomplete. A stale/missing/unknown status also fails closed. If an expected file count exists, `received_files < expected_files` also keeps the job held.

The hold is enforced at multiple layers:

- client upload session;
- `process_job` API before evidence re-registration;
- agent huddle (returns no downstream actions);
- pipeline supervisor (does not dispatch work);
- extraction queue gate;
- task-level safety gates for extraction, parse/shards/buckets, Phase 3, inventory, OCR, RAG/index/append/image embedding/enrichment, graph sync, and report generation.

This means an accidentally queued worker task cannot process a partially transferred multi-segment image.

## Client cleanup

Uploaded client source images are retained while the job is incomplete, failed, paused, or resumable. They are removed only after verified terminal pipeline success. Cleanup is idempotent.

Permanent outputs are not removed: database evidence metadata/hashes, extracted artifacts, RAG/index data, reports, and normal job output remain.

## Server-source cleanup guarantee

Server-local/network/removable evidence is never eligible for browser-upload cleanup. The application never deletes the original examiner/server source under this workflow.

## Validation

V27 targeted intake/source-residency tests: 48 passed.

V25/V26/V27 isolation and semaphore regression subset: 67 passed.

Changed Python modules compile successfully. Changed TypeScript/TSX files pass syntax-only transpilation. A complete Vite dependency build remains unavailable in this sandbox because the supplied project does not contain its npm dependency installation.
