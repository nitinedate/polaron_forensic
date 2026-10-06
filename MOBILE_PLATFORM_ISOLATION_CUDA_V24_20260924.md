# Mobile Platform Isolation + CUDA Capacity Architecture — V24

Date: 2026-09-24

## Objective

Separate Disk Forensics, Android Mobile Forensics, and iOS Mobile Forensics into independent runtime products so that jobs, evidence, RAG indexes, reports, worker queues, and UI navigation cannot bleed across domains. Keep only low-level libraries (hashing/image readers/storage helpers) and the host-capacity governor shared.

## Runtime boundaries

| Boundary | Disk | Android | iOS |
|---|---|---|---|
| API identity | `forensic` | `mobile-android` | `mobile-ios` |
| API port | 8083 | 8081 | 8084 |
| UI | gateway 3000/3001 | compact UI 3002 | compact UI 3004 |
| PostgreSQL | forensic DB | `android_forensic` | `ios_forensic` |
| Redis broker | forensic Redis | Android Redis | iOS Redis |
| MinIO bucket | forensic | `mobile-android` | `mobile-ios` |
| Build queue | `disk-build` | `android-build` | `ios-build` |
| RAG queue | `rag-index` | `android-rag` | `ios-rag` |
| OCR queue | `ocr` | `android-ocr` | `ios-ocr` |
| Report queue | `report-gen` | `android-report` | `ios-report` |
| Data root | Disk data | `data/mobile-android` | `data/mobile-ios` |

Android and iOS also have different Docker Compose projects and different persistent volumes. A job ID from one product is not looked up in a sibling product as a fallback.

## Mobile extraction boundary

The mobile Celery task no longer calls `build_extracted_disk_sync()`.

- `build_extracted_disk()` is the Disk orchestration entrypoint and rejects mobile job types.
- `mobile_forensic/extraction.py` is the mobile orchestration entrypoint.
- Android/iOS ownership is validated before extraction begins.
- Both products may reuse `build_extracted_image()` as a low-level image engine. This is library reuse, not job/backend reuse.

This preserves one implementation of image mechanics while preventing Disk, Android, or iOS orchestration from executing another product's contract.

## Mobile UI

Dedicated mobile builds no longer open the Disk `JobDetailPage` or Disk report editor.

Android and iOS use a compact mobile route tree:

- `/mobile`
- `/mobile/new`
- `/mobile/acquire`
- `/mobile/jobs/:jobId`
- `/mobile/jobs/:jobId/report`

The compact job page contains only mobile acquisition/import, extraction progress, RAG Q&A, and mobile report actions. Cross-backend 404 fallback was removed, so the UI cannot probe another product if a job is missing.

## CUDA

`backend/Dockerfile` now uses an NVIDIA CUDA runtime base. All Aetheris Python forensic/mobile API and Celery application microservices are GPU-visible. GPU visibility is intentionally broader than GPU execution:

- API/build/report/beat workers can read GPU capacity/thermal telemetry.
- OCR and RAG workers may execute heavy CUDA models.
- Heavy CUDA stages must acquire the adaptive shared GPU semaphore first.
- PostgreSQL, Redis, MinIO, Nginx, and vendor vulnerability scanners remain normal infrastructure/vendor containers and do not receive CUDA merely for the sake of uniformity.

## Concurrent server work

Each product has local worker ceilings and an independent broker, so Disk, Android and iOS queues can all make progress at the same time. They coordinate physical host pressure using only:

`redis://host.docker.internal:6389/0`

This capacity Redis stores expiring semaphore leases only. It contains no evidence or job data.

Typical mobile defaults:

- build workers: 3 per mobile product,
- mobile image CPU/I/O ceiling: 3 per product,
- RAG GPU worker: 1 process,
- OCR GPU worker: 1 process,
- report workers: 2 per product,
- live host governor can reduce admission based on CPU temperature, GPU temperature, RAM and VRAM.

On a 12 GB GPU the adaptive governor can keep heavy model concurrency at one even though several API/build/report workers continue in parallel. On a larger/cool GPU it can admit additional work when policy and VRAM thresholds allow.

## Startup

Windows:

```powershell
.\scripts\start-stack.ps1 -Service all
```

The script starts the capacity coordinator first, then current products:

1. Disk Forensics
2. Android Forensics
3. iOS Forensics
4. Vulnerability scanning
5. Disk/Vulnerability gateway

Dedicated Android/iOS UIs remain on ports 3002/3004.

Individual products:

```powershell
.\scripts\start-stack.ps1 -Service forensic
.\scripts\start-stack.ps1 -Service mobile-android
.\scripts\start-stack.ps1 -Service mobile-ios
```

The old `mobile-extract` service remains available only to drain/migrate old deployments. It is not started by `-Service all`.

## Change isolation rule

New platform-specific features should be added in product/domain modules first:

- Android behavior: Android service/agent/queue modules.
- iOS behavior: iOS service/agent/queue modules.
- Disk behavior: Disk service/queue modules.

Move code into a shared library only when it is genuinely platform-neutral (for example hashing, neutral image reading, MinIO primitives, telemetry, or semaphore mechanics). Do not add sibling API fallback, cross-product database access, or shared evidence buckets.

## Validation

Current V24 validation (93 targeted tests passing) includes:

- hard Android/iOS/Disk service admission,
- non-overlapping Android/iOS queue names,
- separate DB/Redis/MinIO volumes,
- mobile task does not call Disk orchestration,
- Disk orchestration rejects mobile jobs,
- mobile compact UI does not mount the Disk job detail/report route,
- all Python mobile microservices have CUDA visibility,
- shared capacity Redis is distinct from each product's Celery broker,
- `start-stack.ps1 -Service all` selects Android + iOS products, not the legacy combined mobile service,
- Disk/mobile path classifier isolation.

## Additional isolation hardening

The final V24 pass also enforces the boundary below the API/UI layer:

- Android and iOS Celery worker entrypoints reuse the exact Celery instance that decorates `app.tasks`; this prevents a second app registry and avoids unregistered-task failures.
- HostDrive mobile-device responses are filtered to the current product. Android never receives iOS devices from `/api/hostdrive/mobile-devices` or `/api/hostdrive/acquisition/devices`, and iOS never receives Android devices.
- Server-side evidence mounts are platform-private by default:
  - Android: `${ANDROID_HOST_EVIDENCE_PATH:-./evidence/android}` mounted as `/evidence`.
  - iOS: `${IOS_HOST_EVIDENCE_PATH:-./evidence/ios}` mounted as `/evidence`.
- Android and iOS MinIO bucket names are fixed to `mobile-android` and `mobile-ios` inside their physically separate MinIO instances rather than inheriting a shared root `.env` bucket name.
- The mobile extraction boundary compares canonical job ownership with evidence metadata. If an Android job clearly contains iOS ownership/adapter/path metadata (or the reverse), extraction is refused before the neutral image engine is entered.

## Capacity admission behavior

Extraction now uses fail-closed host admission. If the live shared CPU/I/O semaphore has no capacity, the Disk/Android/iOS Celery extraction task does **not** start anyway. It releases the worker execution and retries after 15 seconds (up to the long-job retry budget). This lets all product queues remain active while the shared host governor decides which work can enter CPU/I/O-heavy execution.

The intended concurrency model is therefore:

```text
Disk queue ---------\
Android queue -------+--> shared host CPU/I/O permits --> extraction/readers
IOS queue -----------/

Android RAG ---------\
IOS RAG --------------+--> shared host GPU permits ----> CUDA models
Disk RAG -------------/
```

Each product keeps its own database, broker, object store, queues, and job lifecycle. Only short-lived capacity leases cross the product boundary.

## Final targeted regression result

The architecture/isolation/capacity suite currently reports **93 passed**. This covers service admission, queue separation, platform-private evidence stores, mobile-vs-Disk extraction boundaries, Celery registry wiring, HostDrive device filtering, CUDA visibility, adaptive CPU/GPU capacity, stale-lock recovery, and compact mobile UI routing.
