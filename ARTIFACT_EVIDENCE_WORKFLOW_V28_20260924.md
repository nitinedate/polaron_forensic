# Polaron / Aetheris Artifact Evidence Workflow V28 — 2026-09-24

## Purpose
V28 makes Artifact Review a first-class forensic stage and keeps Disk and Mobile evidence review separate.

The enforced examiner workflow is:

**Processing Pipeline → Artifacts → Intake → Report**

Processing pages no longer provide direct Intake or Report creation links. Intake is reached from the relevant Artifact workspace, and Report is reached from Intake after the intake gate is satisfied.

## Disk Artifacts

### Navigation
- New sidebar route: `/forensic/artifacts`
- Case ID / job ID filter
- Per-job explorer route: `/forensic/jobs/{job_id}/artifacts`

### Evidence presentation
Disk Artifacts continues to use the existing category/subcategory evidence catalog and now emphasizes actual evidence-file review:
- images/photos
- video
- audio
- PDF/TXT/Office documents
- EML/EMLX/MSG/mail stores and attachments
- LNK/shortcut evidence
- Jump Lists
- logs/event evidence
- web/chat/social evidence
- deleted/recovered files
- carved/extensionless/anomalous files

The original evidence content endpoint remains the source for preview/download. The UI does not substitute web thumbnails for original evidence downloads.

### Actual media properties
New endpoint:

`GET /api/jobs/{job_id}/artifacts/{artifact_id}/properties`

It returns, where available:
- actual evidence size in bytes
- MIME/type and format
- image/video width and height
- total pixel count
- audio/video duration
- video/audio codec information
- audio sample rate/channels
- deletion/recovery state
- SHA-256
- original evidence download URL

Image dimensions prefer indexed evidence metadata and otherwise probe the original evidence bytes with Pillow/HEIF support. Audio/video properties use persisted metadata when available and otherwise `ffprobe`. The backend CUDA application image now includes ffmpeg/ffprobe.

### Examiner review signals
New endpoints:

- `GET /api/jobs/{job_id}/artifact-review`
- `GET /api/jobs/{job_id}/artifacts/{artifact_id}/review`

Signals cover evidence that warrants examiner attention, including:
- executable/active content
- double extensions
- extension/signature mismatch
- LNK and Jump List execution context
- PowerShell/cmd/LOLBins
- email link/attachment context
- IP-literal and punycode URLs
- social/messaging traces
- log content with command/sensitive indicators
- deleted/recovered evidence
- modified/renamed/recovered filesystem state
- OCR/derived media text containing review-sensitive concepts

These are **review/triage signals**, not conclusions about maliciousness, intent, identity, or guilt. The original evidence must be inspected by the examiner.

The case-level review summary is bounded so a multi-million-file image is not loaded into Python. It performs database-side candidate screening with a hard scan cap; deep OCR/parsed-content/image-description review is performed on the selected artifact.

### Email safety and attachments
Recovered HTML email/HTML evidence is rendered inside a sandboxed iframe with a restrictive CSP. Scripts, forms, frames, navigation/base changes, and remote resources are blocked to prevent recovered evidence from executing or beaconing from the examiner browser.

MIME attachments can be opened and explicitly downloaded. Indexed attachments download through the normal original-artifact content endpoint.

## Mobile Artifacts

Mobile uses a different UI and remains physically separated from Disk.

### Navigation
- Directory: `/mobile/artifacts`
- Android: `/mobile/android/jobs/{job_id}/artifacts`
- iOS: `/mobile/ios/jobs/{job_id}/artifacts`
- Dedicated mobile service: `/mobile/jobs/{job_id}/artifacts`

The directory may list Android and iOS jobs for navigation, but evidence stays in the platform-specific backend/database/broker/object store. Selecting a job pins the examiner to the corresponding Android or iOS route.

### Mobile workspace tabs
- Overview
- WhatsApp
- Media & files
- Deleted evidence

The Deleted Evidence tab is intentionally separate from current/live evidence and includes deleted WhatsApp, deleted photos, deleted videos, deleted documents, and other recovered deleted files.

### WhatsApp-style examiner view
WhatsApp messages are presented as chat bubbles:
- device-owner messages on the right
- other participants on the left
- current and recovered/deleted messages clearly marked
- `deleted by me` distinction retained when recovered metadata supports it
- message time and sender identity displayed
- linked image/video/audio/document evidence shown in the message
- original linked media can be opened/downloaded
- recovery state, classification, confidence, and provenance retained

Cross-app person grouping was corrected so the same normalized person recovered from WhatsApp/SMS/Telegram is not unnecessarily duplicated simply because each app uses a different conversation ID.

### Mobile media
Mobile Artifacts provides dedicated families for:
- pictures/images
- videos
- audio/voice notes
- documents/PDF/TXT/Office
- WhatsApp media
- deleted photos
- deleted videos
- deleted documents
- deleted files

Selecting a file opens the shared evidence preview component, which reports original size, dimensions/pixels/duration when available and provides original-file download.

## Workflow enforcement

### Disk
`/forensic/jobs/{id}` → `/forensic/jobs/{id}/artifacts` → `/forensic/jobs/{id}/intake` → `/forensic/jobs/{id}/report`

### Android
`/mobile/android/jobs/{id}` → `/mobile/android/jobs/{id}/artifacts` → `/mobile/android/jobs/{id}/intake` → `/mobile/android/jobs/{id}/report`

### iOS
`/mobile/ios/jobs/{id}` → `/mobile/ios/jobs/{id}/artifacts` → `/mobile/ios/jobs/{id}/intake` → `/mobile/ios/jobs/{id}/report`

The Intake page sends the examiner back to Artifacts and only enables/links forward to Report when the existing intake/report-ready gate is satisfied.

## Isolation guarantees retained
- Disk Artifacts uses the Disk backend/data store.
- Android Artifacts uses Android jobs/data only.
- iOS Artifacts uses iOS jobs/data only.
- Mobile routes do not fall back to Disk on 404.
- Artifact work does not change the V25 shared physical CPU/GPU capacity model.
- LaptopScanner remains independent and its IP semaphore is unaffected.
- V27 server-local zero-copy/client-upload residency rules remain unchanged.

## Performance notes
- Artifact list browsing remains paginated/virtualized.
- Review summaries do not load a whole case into Python.
- Deep content review runs only for selected evidence.
- Media probing prefers already indexed metadata before reading evidence bytes.
- A configurable `ARTIFACT_MEDIA_PROBE_MAX_BYTES` ceiling protects the API from accidentally spooling unbounded media into a temporary probe file (default 20 GiB).

## Validation
Performed in the available sandbox:
- V28 artifact workflow: 13/13 passed.
- Combined Disk/Mobile artifact + V26/V27/V25 regression selection: 85/85 passed.
- LaptopScanner: 41/41 passed.
- Intake/report subset: 35 passed, 1 deselected because the sandbox does not have the runtime `psycopg2` PostgreSQL driver required by that single report-generator import.
- Changed Python modules compile successfully.
- All changed TS/TSX files pass TypeScript syntax transpilation using TypeScript 5.8.3.

A full Vite dependency/type-resolution build is not possible from this extracted source tree because `frontend/node_modules` is not present. The production frontend Docker build installs dependencies from `package-lock.json`.
