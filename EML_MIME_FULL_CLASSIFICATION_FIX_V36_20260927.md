# Polaron V36 - EML preview and full MIME classification fix

Date: 2026-09-27

## Problems fixed

1. Signature-carved EML rows such as `Carved EML @ pagefile.sys:<offset>` were only virtual inventory rows. The React preview therefore showed the old signature-hit text instead of opening the recovered RFC822 message.
2. V35 sampled large pagefile/hiberfil files in windows but stored offsets relative to a synthetic concatenation. A stored carve offset could therefore point to the wrong location when the user later opened it.
3. Generic or extensionless artifacts could remain `application/x-forensic-data` even when a byte signature could identify PDF, email, image, SQLite, Office, archive, media, and other formats.
4. The artifact page did not expose job-wide MIME classification progress.

## V36 behavior

### Carved EML is now openable

`carve-*` artifacts are first-class read-only evidence objects. The backend reopens only the bounded byte range at the recorded source offset (or unallocated inode), without copying or altering the E01/source evidence.

For a recovered RFC822 message the third panel returns:

- From / To / Cc / Bcc
- Subject
- Date and Message-ID
- Plain-text body
- Sandboxed HTML body
- Raw RFC source tab
- MIME attachment list
- Attachment MIME type, size and filename
- Open/download for each recoverable attachment

EML/EMLX parsing uses Python's standard-library `email` MIME parser. V35's `extract-msg`, `python-magic/libmagic`, and `pst-utils/readpst` dependencies remain in place for MSG, generic MIME detection and PST/OST workflows.

### Exact pagefile / unallocated offsets

Signature inventory version is bumped to v3. Existing V35 carve caches are automatically rejected and rebuilt from the existing mounted evidence. The rebuild does not re-download, copy or re-extract the E01.

Pagefile/hiberfil scan windows now retain their real logical-file offsets. Unallocated hits retain the source inode. When an examiner selects a carved item, Polaron reads only that bounded range from the original virtual disk.

### MIME classification for all artifacts

Every `job_artifacts` row receives versioned MIME/type metadata. To keep large cases fast:

- known formats use trusted parser/path/extension metadata first;
- generic, extensionless, cache, `.dat`, `.bin`, `.tmp`, `.blob` and unresolved files are byte-sniffed;
- byte sniffing uses Polaron signatures plus libmagic where available;
- RFC822 headers are recognized before generic text detection, so extensionless email becomes `message/rfc822` / `.eml`;
- classification metadata is persisted to PostgreSQL;
- the work runs in bounded Celery batches and the Artifact page reports MIME scan progress.

The source evidence bytes, source filename and source hash are never changed. `normalized_filename` is an examiner-facing derived/open/download name only.

A truly unrecognized object remains `application/x-forensic-data`; Polaron does not invent a false MIME type. Its third panel now opens a safe forensic-data inspector showing readable strings (ASCII/UTF-16) and an Open/Download action rather than a hex/binary dump.

## AXIOM display correction for carved rows

Carved rows now keep the AXIOM hierarchy in the detail pane, for example:

- `Email & Calendar > EML(X) Files`
- `Email & Calendar > Outlook Emails`
- `Media > Pictures`
- `Media > Videos`
- `Documents > PDF Documents`

rather than displaying the internal `eml`, `jpeg`, etc. kind as the category.

## Main changed files

- `backend/app/services/virtual_disk.py`
- `backend/app/services/signature_carve_inventory.py`
- `backend/app/services/carved_artifact_content.py` (new)
- `backend/app/services/artifact_mime_inventory.py` (new)
- `backend/app/services/artifact_type_resolver.py`
- `backend/app/services/artifact_preview.py`
- `backend/app/routers/artifacts.py`
- `backend/app/tasks.py`
- `frontend/src/lib/artifactContent.ts`
- `frontend/src/lib/types/forensic.ts`
- `frontend/src/components/forensic/ArtifactPreviewPanel.tsx`
- `frontend/src/pages/forensic/ArtifactExplorerPage.tsx`
- `backend/tests/test_carved_email_mime_v36.py` (new)
- `backend/tests/test_artifact_mime_inventory_v36.py` (new)

## Validation performed

- 116 focused backend regression tests: PASS
- Python compilation of all modified backend modules: PASS
- TypeScript syntax transpilation of all modified frontend TS/TSX files: PASS

## Deployment

From the Polaron project root:

```powershell
docker compose up -d --build api worker-disk worker-parse worker-rag-gpu worker-agent frontend
```

Then hard-refresh the browser with `Ctrl+Shift+R`.

When the Artifacts page is opened, V36 automatically queues the MIME inventory for existing artifacts. Existing V35 signature-carve inventory is rebuilt to v3 on demand so carved EML offsets become openable. Neither operation re-downloads or re-extracts the disk image.
