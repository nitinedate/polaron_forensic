# Aetheris Mobile Artifacts Completeness Fix V18

Date: 2026-09-20

## Scope

This patch changes the Mobile Forensic artifact pipeline so large Android/iOS and imported mobile evidence collections are processed as complete evidence sets instead of previews/samples. It also adds direct normalized-mobile-artifact RAG indexing, explicit processing coverage, stable artifact IDs, and stricter deleted-evidence semantics.

The patch does **not** claim that a logical acquisition can recover deleted data that was never acquired. Deleted/recovered evidence is reported only when a supporting database flag/table, recovery source, file-system remnant, or other evidentiary basis is present.

## Main fixes

### 1. Removed mobile completeness ceilings

Old behavior included:

- inventory persistence truncated to the first 200,000 items;
- parsing limited to the first 50,000 files;
- several SQLite parsers used hard row limits such as 2,000/3,000/5,000;
- case package export truncated inventory/artifacts/timeline at 500,000/100,000/50,000.

New behavior:

- all discovered inventory items are persisted in bounded batches;
- every discovered file is routed through the parser registry;
- evidentiary SQLite tables are streamed with `fetchmany()` and no implicit row cap;
- large case exports use ZIP64 + streamed JSONL datasets, with no global export row cap.

### 2. Resumable/deterministic normalized artifacts

`NormalizedArtifact.create()` now generates deterministic `MOB-...` IDs from the evidence identity (job, source path, table/row/offset, state and stable record identifiers). Re-analysis therefore updates the same artifact instead of creating duplicates after a worker restart.

### 3. Expanded WhatsApp parsing

The WhatsApp parser now handles Android/iOS schema variants and streams complete tables for:

- messages;
- conversations/chats;
- contacts/JIDs;
- calls;
- attachment/media references;
- encrypted backup sidecars;
- explicit deleted/revoked flags where the source schema provides them.

Important files such as `msgstore.db`, `wa.db`, `ChatStorage.sqlite` and supported call databases are normalized with source-path/table/row provenance.

### 4. Media/document artifact coverage

The file/media parser now classifies a broader set of:

- images;
- video;
- audio and voice notes;
- documents;
- archives;
- downloads;
- WhatsApp/Telegram/Signal/social-app media;
- camera files;
- cache-derived files;
- trash/recovered paths.

WhatsApp media receives `artifact_family=whatsapp_media` and a media subtype such as image/video/audio/voice_note/document/sticker/status where detectable.

### 5. Correct deleted/recovered evidence semantics

The old recovery analyzer could label the mere presence of `*-wal` as recovered evidence. This is not forensically correct. The legacy SQLite residual carver also stopped at 5,000 main strings, 3,000 WAL strings, and 800 structured residuals; those hard ceilings have been removed.

New behavior:

- WAL/journal/SHM presence -> `state=unverified`, recovery-source artifact only;
- explicit deleted/recovered database rows -> `database_deleted`;
- positive SQLite freelist -> `freelist_candidate` until carved/validated;
- trash/recently-deleted paths -> `filesystem_recovered`;
- orphaned messaging media -> `orphaned` with a stated limitation;
- cache/thumbnail-derived evidence -> `cache_derived`;
- chat-like SQLite freelist/WAL/journal residuals -> normalized `recovered_chat_candidate` records with `state=unverified`, provenance and examiner-validation warning, so they can enter RAG without being presented as confirmed deleted messages.

The UI can therefore distinguish a **recovery source** from an **actual recovered record**.

### 6. Direct Mobile RAG bridge

A new `mobile_rag.py` indexes `mobile_normalized_artifacts` directly into `rag_chunks`.

This includes live and recovered/deleted normalized records instead of depending only on `job_artifacts`.

RAG text includes provenance fields such as:

- artifact ID/type/domain;
- timestamp;
- evidence state;
- source path/table/row;
- recovery source;
- application/conversation/message/media fields.

Embeddings are used when the configured embedding service is available; text chunks are still created if embeddings are unavailable.

### 7. Processing run and coverage tracking

Added runtime schema support for:

- `mobile_analysis_runs`
- `mobile_coverage`

The pipeline records phases and counters for inventory, parsing, recovery and RAG. Coverage rows show discovered, processed, artifact, error and status counts per evidence family.

### 8. Mobile Artifact Board integration

The mobile artifact-board API now merges authoritative normalized artifact-family counts with the package/file inventory. This prevents WhatsApp/SMS/call/deleted records parsed from SQLite from being hidden by filename-only inventory counts.

The React Mobile Artifact Board also accepts and displays processing coverage information.

### 9. Complete case export

`case_export.py` now writes complete large collections using JSONL streams:

- `inventory/inventory.jsonl`
- `parsed/artifacts.jsonl`
- `recovered/candidates.jsonl`
- `reports/timeline.jsonl`

The historical JSON paths remain for compatibility and are now manifests pointing at the complete JSONL files:

- `inventory/inventory.json`
- `parsed/artifacts.json`
- `recovered/candidates.json`
- `reports/timeline.json`

The package uses ZIP64 and records SHA-256 hashes for exported members.

## New/modified files

### New

- `backend/app/services/mobile_forensic/coverage.py`
- `backend/app/services/mobile_forensic/mobile_rag.py`
- `backend/tests/test_mobile_artifacts_completeness_v2.py`
- `MOBILE_ARTIFACTS_COMPLETENESS_FIX_V18_20260920.md`

### Modified

- `backend/app/services/mobile_forensic/models.py`
- `backend/app/services/mobile_forensic/storage.py`
- `backend/app/services/mobile_forensic/pipeline.py`
- `backend/app/services/mobile_forensic/case_export.py`
- `backend/app/services/mobile_forensic/correlation.py`
- `backend/app/services/mobile_forensic/parsers/_sqlite_util.py`
- `backend/app/services/mobile_forensic/parsers/messaging.py`
- `backend/app/services/mobile_forensic/parsers/files_media.py`
- `backend/app/services/mobile_forensic/parsers/sms_calls.py`
- `backend/app/services/mobile_forensic/parsers/contacts.py`
- `backend/app/services/mobile_forensic/parsers/browser.py`
- `backend/app/services/mobile_forensic/parsers/calendar_notes.py`
- `backend/app/services/mobile_forensic/parsers/location.py`
- `backend/app/services/mobile_forensic/recovery/analyzers.py`
- `backend/app/services/mobile_acquire/sqlite_deleted.py`
- `backend/app/routers/jobs.py`
- `frontend/src/components/forensic/MobileArtifactBoard.tsx`

## Regression tests added

`backend/tests/test_mobile_artifacts_completeness_v2.py` verifies:

1. a WhatsApp database containing 5,501 messages produces all 5,501 message artifacts (no old 5,000-row parser ceiling);
2. the same source record receives the same deterministic artifact ID on rerun;
3. WAL presence is not mislabeled as a recovered message;
4. a WhatsApp document under a deleted/trash path remains categorized as WhatsApp media and receives `filesystem_recovered` state;
5. SQLite residual carving is not silently cut off at the old 5,000-string ceiling.

Focused mobile/WhatsApp modified-area suite result:

```text
36 passed
```

A broader mobile suite result after this patch:

```text
123 passed, 6 failed
```

The six broad-suite failures are outside this patch's modified area: five reproduce on the unmodified baseline (mobile capability label, objective/report fallback expectations, PAS segment classification and Windows/mobile include filtering), and one cannot import `psycopg2` in the current test environment.

Frontend `npm run lint` could not be used as a clean validation signal because the supplied project copy does not contain the declared React/React Router/Lucide/type dependencies in `node_modules`; TypeScript therefore reports missing-module/JSX-runtime errors across the existing frontend, not only this component.

## Deployment

After copying the modified project to the server, rebuild the affected backend/frontend services using the deployment method already used by Aetheris. At minimum, restart the API/worker processes so `ensure_mobile_case_schema()` creates the new run/coverage tables and the worker loads parser version 2.0 classes.

For an existing mobile job, rerun the normalized mobile analysis with force/re-analysis enabled so old sampled results are replaced/upserted using deterministic IDs and the complete RAG bridge is populated.

## Expected post-fix completion invariant

For a successful mobile analysis run:

```text
inventory_discovered == files_processed
all_files_processed == true
global_file_cap == null
global_row_cap == null
```

Individual artifact families may still legitimately be absent when the acquisition did not contain them. In particular, deleted WhatsApp cannot be guaranteed from a logical/MTP-only acquisition when the relevant private app database/WAL/file-system remnants were never acquired.
