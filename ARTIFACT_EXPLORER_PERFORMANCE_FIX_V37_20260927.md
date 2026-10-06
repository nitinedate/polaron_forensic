# Polaron V37 - Artifact Explorer performance and HTTP 500 fix

Date: 2026-09-27

## Symptoms fixed

- Artifact Explorer left tree loaded, but the center artifact list remained empty or took a long time.
- The right preview/details column appeared to hang because the list could not select a usable row quickly.
- Browser console repeatedly showed `GET /api/jobs/<job>/artifacts... 500 (Internal Server Error)`.
- While AXIOM/MIME inventory was still running, the UI retried the expensive artifact list repeatedly and amplified the failure.

## Root causes

1. **DDL in the artifact GET hot path.** `ensure_evidence_browse_indexes()` was keyed by SQLAlchemy Session identity. A new Session is created per request, so `CREATE INDEX IF NOT EXISTS` / extension checks could execute on every list request. Under active workers this created PostgreSQL lock contention and could cascade into 500s.
2. **Catalog UPSERTs in the artifact GET hot path.** `ensure_extended_encyclopedia()` was called from artifact list/detail GETs and performed `INSERT ... ON CONFLICT DO UPDATE` repeatedly.
3. **AXIOM catalog/schema repair in polled GETs.** Categories/progress polling could import/repair catalog rows and run schema compatibility DDL while the examiner was browsing.
4. **Synchronous signature-carve scans from interactive browse.** Missing carve inventory could trigger hundreds of MB/GiB of pagefile/unallocated scanning inside a GET request.
5. **Frontend request storm.** While processing/inventory was active, the page refreshed the artifact list every five seconds. One failing list query therefore produced a continuous series of 500 responses.
6. **Redundant detail calls.** Selecting a list row re-fetched the same artifact and requested a graph endpoint although the list row already carried the needed metadata.
7. **Third-panel contention.** Media properties could perform image/ffprobe/evidence-byte reads while preview and deep review were also starting.
8. **EML browse predicates were not fully index-friendly.** Windows EML browsing included broad path `ILIKE` fallbacks and MIME expressions that did not exactly match the available expression indexes.
9. The package referenced `migrations/037_search_performance_indexes.sql`, but the migration was missing from the previous release.

## V37 changes

### PostgreSQL / indexes

`migrations/037_search_performance_indexes.sql` now creates per-firm browse indexes once, outside HTTP GET handlers:

- `ix_job_artifacts_job_path`
- `ix_job_artifacts_job_file_name`
- `ix_job_artifacts_job_file_name_lower`
- `ix_job_artifacts_job_ext`
- `ix_job_artifacts_job_enc`
- `ix_job_artifacts_job_size`
- `ix_job_artifacts_job_name_size`
- `ix_job_artifacts_job_mime_resolved`
- `ix_job_artifacts_job_mime`
- `ix_job_artifacts_job_mime_resolved_lower`
- `ix_job_artifacts_job_mime_lower`
- `ix_job_artifacts_job_mime_scan_version`
- pending parse/OCR indexes
- artifact parse-result indexes
- AXIOM result lookup index
- optional `pg_trgm` GIN indexes on `file_path` and `file_name`

The migration runs `ANALYZE` after index creation so PostgreSQL can use the new plans immediately. `scripts/apply_migrations.ps1` and `scripts/apply_migrations.sh` now include migration 037.

For live systems, `backend/scripts/apply_search_indexes_v4_8.py` can build the browse indexes with `CREATE INDEX CONCURRENTLY` to avoid blocking evidence workers.

### Backend hot-path fixes

- `ensure_evidence_browse_indexes()` is now a compatibility no-op. DDL is applied at startup/provisioning/migration only.
- Extended encyclopedia rows are seeded once during API startup, not per artifact request.
- `/artifacts/categories` is read-only. It no longer imports the AXIOM catalog, runs schema DDL, or queues worker tasks on every 10-second UI poll.
- AXIOM and MIME progress reads have pure-read modes for the explorer.
- Signature-carve browse reads only persisted/cache inventory. Heavy carving remains a worker responsibility.
- Corrupt/stale carve cache is treated as optional enrichment; it cannot turn the normal artifact list into HTTP 500.
- Fast artifact properties use persisted metadata and do not read evidence bytes or run `ffprobe`/image decoding unless explicitly requested.
- Carved properties do not reread the same source range while preview is loading.
- Windows/Linux `EML(X) Files` browse uses exact extension/MIME predicates backed by expression indexes. macOS retains Apple Mail path fallbacks.
- Compatibility columns previously repaired by GET handlers are now created during startup/migration.

### Frontend fixes

- Artifact list is no longer polled every five seconds while inventory is running. Only the lightweight tree/progress endpoint refreshes every ten seconds.
- Identical in-flight list requests are deduplicated.
- Artifact search is debounced by 300 ms.
- On a list failure the center panel clears stale totals/items and shows one explicit Retry state instead of `39 matching` + `No artifacts found` while the console floods with errors.
- Selecting an artifact uses the row already returned by `/artifacts`; the redundant `/artifacts/{id}` request was removed.
- Graph rendering uses artifact metadata directly and does not issue a graph request on every selection.
- Properties load independently from preview; deep review is deferred and does not block the visible third-panel metadata.
- File tree remains lazy and is only fetched when the examiner opens the File Tree tab.

## Verification utilities

From the API/backend environment:

```bash
python scripts/verify_artifact_browse_indexes_v37.py --schema firm_polaron
python scripts/diagnose_artifact_explorer_v37.py --schema firm_polaron --job-id <job-uuid>
```

The first command reports required/optional index presence. The second also prints PostgreSQL `EXPLAIN` output for the hot EML list query.

## Validation performed

- Python compileall: passed.
- Focused V37/artifact tests: passed.
- Artifact/email/AXIOM regression suite: 137 passed.
- Modified TypeScript/TSX files: syntax transpilation passed.

## Deployment

For a live database, build indexes concurrently first:

```powershell
# Run from project root after copying V37 files.
docker compose exec api python scripts/apply_search_indexes_v4_8.py --schema firm_polaron

docker compose exec api python scripts/verify_artifact_browse_indexes_v37.py --schema firm_polaron

docker compose up -d --build api worker-disk worker-parse worker-rag-gpu worker-agent frontend
```

Alternatively, during a maintenance window:

```powershell
powershell -ExecutionPolicy Bypass -File .\scripts\apply_migrations.ps1
docker compose up -d --build api worker-disk worker-parse worker-rag-gpu worker-agent frontend
```

Then hard-refresh Chrome (`Ctrl+Shift+R`).
