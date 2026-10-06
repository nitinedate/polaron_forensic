# Polaron V31.2 - Disk Artifacts console 404 fix

Date: 2026-09-26

## Symptom

The Disk Artifacts page rendered correctly, but Chrome DevTools showed:

`GET /api/jobs/<job-id> 404 (Not Found)`

This was a redundant job-detail request made only to learn whether the artifact page should keep polling while extraction/RAG was active.

## Root cause

Two things could produce the noisy 404:

1. `ArtifactExplorerPage` separately called `GET /api/jobs/{job_id}` even though it had already called the artifact-category endpoint.
2. A job id could remain pinned in browser localStorage to an old physical backend (for example `mobile-android`) after earlier builds misclassified a disk job. `inferApiService()` honored that stale pin before the visible `/forensic/...` route, so the job-detail request could be sent to the wrong isolated backend and return 404.

The artifact list itself could still load after the stale pin was cleared, which is why the page was usable while the console showed an error.

## Fix

### Backend

`GET /api/jobs/{job_id}/artifacts/categories` now also returns lightweight job state:

- `job_exists`
- `job_status`
- `job_progress_pct`

No additional expensive inventory reconciliation is performed.

### Frontend

`ArtifactExplorerPage` now uses `job_status` returned by the artifact-category request and no longer calls `GET /api/jobs/{job_id}` just for polling state.

### API routing isolation

Product-specific browser routes are now authoritative:

- `/forensic/...` -> `forensic`
- `/mobile/android/...` -> `mobile-android`
- `/mobile/ios/...` -> `mobile-ios`
- `/forensic/mobile/...` -> `mobile-extract`
- `/vuln/...` -> `vuln`

A stale localStorage job mapping can no longer override the visible product route. Cross-product 404 fallback remains disabled, so service isolation is preserved.

## Changed files

- `backend/app/routers/artifacts.py`
- `backend/tests/test_artifact_console_404_v31_2.py`
- `frontend/src/lib/apiRouting.ts`
- `frontend/src/lib/forensicApi.ts`
- `frontend/src/lib/types/forensic.ts`
- `frontend/src/pages/forensic/ArtifactExplorerPage.tsx`

## Validation

59 focused regression tests passed, including artifact rendering, dashboard routing, server-local zero-copy, mobile isolation, and donut theme tests.

Python compilation passed for the modified backend router.

The four modified TypeScript/TSX source files were syntax-transpiled successfully with TypeScript 5.8.3.

## Deployment

Rebuild the forensic API and gateway/frontend after replacing the files. Then hard-refresh Chrome (`Ctrl+Shift+R`).

The Disk Artifacts page should continue to display normally and Chrome DevTools should no longer show the redundant `GET /api/jobs/<job-id> 404` request.
