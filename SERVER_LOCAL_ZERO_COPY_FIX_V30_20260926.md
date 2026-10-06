# Server-local E01 zero-copy intake fix (V30 - 2026-09-26)

## Problem

A disk image selected in the browser was being sent through the Download Agent even when the `.E01/.E02/...` files were already physically attached to the forensic server on an internal HDD/SSD, USB pen drive, or external HDD. Chrome's folder picker does not expose the absolute Windows path, so the UI incorrectly treated the selection as remote client evidence and started HTTP upload/staging.

The same job could also show Android/iOS ownership when stale mobile metadata remained in `disk_source`.

## Correct behavior

For a disk-forensics job, before any upload starts the UI now asks the server to locate the exact selected E01 segment set on server-visible drives. Matching uses the selected segment filenames plus exact byte sizes. When a match is found:

1. The server path is registered directly.
2. `intake=server_local` and `source_residency=server_local` are persisted.
3. No browser upload is started.
4. No staging/object-storage copy is made.
5. The Download Agent is marked `Skipped - zero copy` rather than run.
6. List Folder, Get Segments, Virtual Disk, and Extraction read the source in place.
7. E01 segments are opened from their registered host paths by the existing EWF/virtual-disk reader.
8. The original source is never deleted by client-upload cleanup (`cleanup_policy=never_delete_source`).

When the console is running on `localhost` and the selected E01 cannot be resolved after one drive-mount refresh, the UI fails closed and refuses to upload the disk image. The examiner is asked to select/refresh the server/removable drive so the image is processed in place.

Remote-client evidence still uses the Download Agent and its parallel HTTP intake, because in that case the files genuinely are not present on the forensic server.

## Server-side safety gate

`POST /jobs/{job_id}/evidence/begin-client-upload` now rejects a client upload if that job is already registered as server-local and has a server-local evidence path. This prevents an old/stale browser from flipping a zero-copy job back to `browser_upload` and duplicating a very large E01.

## Mobile/disk isolation

A `host_disk` job is no longer classified as Android/iOS merely because stale `mobile_os` metadata exists. Registering server-local disk evidence also clears upload and mobile ownership markers that are invalid for a disk job.

## Files changed

- `backend/app/routers/jobs.py`
- `backend/app/schemas/forensic.py`
- `backend/app/services/host_evidence.py`
- `backend/app/services/pipeline_orchestrator.py`
- `backend/app/services/action_agents.py`
- `frontend/src/components/forensic/HostEvidencePanel.tsx`
- `frontend/src/lib/forensicApi.ts`
- `frontend/src/lib/orchestrationStages.ts`
- `frontend/src/lib/jobUploadSession.ts`
- `backend/tests/test_server_local_zero_copy_v30.py`

## Validation

- Python compilation: passed.
- Zero-copy / residency / cleanup / drive-mount / Download Agent / pre-intake regression suite: **38 passed**.
- Modified frontend TS/TSX syntax transpilation: passed for all four files.
- A broader existing suite exposed unrelated pre-existing failures (`mobile-parse` vs `mobile-build` expectation and missing `psycopg2` in the sandbox); these are not introduced by this patch.
