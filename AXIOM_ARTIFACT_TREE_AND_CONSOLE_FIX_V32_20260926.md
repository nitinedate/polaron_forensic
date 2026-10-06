# Polaron V32 - AXIOM Artifact Tree + Artifact Console Fix

Date: 2026-09-26

## Problems fixed

1. The Disk Artifacts tree displayed Polaron internal encyclopedia identifiers such as `DOC-IMAGE-0001`, `USR-APPDATA-0001`, and `SYS-WINDOWS-*` instead of forensic artifact names from the AXIOM reference catalog.
2. Counts in the left tree were raw internal file-family counts rather than persisted AXIOM-aligned artifact counts.
3. Selecting artifacts generated repeated browser-console `404 (Not Found)` responses because the React graph panel called `/api/jobs/{job_id}/artifacts/{artifact_id}/graph`, but that API route did not exist.
4. The file-tree endpoint returned an old `{entries: [...]}` payload while React expected `{summary,nodes,root}`.
5. File-tree data (up to 5,000 paths) was requested again on every artifact selection even when the examiner never opened the File tree tab.

## V32 behavior

### AXIOM names + counts

The explorer tree is now built from `public.axiom_artifacts` and the persisted `job_axiom_artifact_results` inventory.

- Parent: AXIOM category.
- Child: exact artifact name from the bundled Magnet AXIOM 10.2 reference.
- Count: persisted occurrence/artifact count produced by the AXIOM inventory runner.
- Filter: stable `catalog_key`/artifact id, not the display label.
- Whole-category browsing: `catalog_section`.
- Internal `DOC-*`, `USR-*`, `SYS-*`, and `FS-*` ids are no longer emitted as the explorer taxonomy.

The raw evidence-file total (`All artifacts`) remains separate from AXIOM record counts because one source file/database may produce many forensic records and count domains can overlap.

### Full AXIOM 10.2 reference

`data/axiom/Magnet_AXIOM_10.2.0_All_Artifacts.csv` is bundled with the project. It contains the full artifact reference used by the application instead of relying on the earlier small report-template seed.

Startup catalog loading now imports the CSV when the grouped workbook is not present. Existing report-template catalog ids are preserved when they already represent the same artifact name, so previously persisted job counts are not orphaned.

### Existing jobs

A job processed before V32 may have only the old partial catalog inventory. When the Artifacts page is opened, V32 detects that the full catalog has more definitions and queues only the missing AXIOM inventory pass. It does **not** re-download, copy, or re-extract the E01 evidence.

The Artifacts page polls the inventory while this backfill is running and updates counts in place.

### Console 404 fix

Added:

`GET /api/jobs/{job_id}/artifacts/{artifact_id}/graph`

Graph enrichment is optional. If a selected artifact or virtual evidence row has no graph data, the endpoint returns HTTP 200 with empty `entities` and `relationships`; it does not create a console 404.

### File-tree performance

`GET /api/jobs/{job_id}/file-tree` now returns the React `JobFileTree` contract:

- `summary`
- `nodes`
- `root`
- `disk_artifact_id`
- legacy `entries` compatibility field

The frontend fetches the potentially large file tree only after the examiner opens the **File tree** tab, instead of on every artifact click.

## Main changed files

- `backend/app/routers/artifacts.py`
- `backend/app/services/catalog_ingest.py`
- `frontend/src/pages/forensic/ArtifactExplorerPage.tsx`
- `frontend/src/components/forensic/ArtifactCategoryTree.tsx`
- `frontend/src/components/forensic/ArtifactGraphPanel.tsx`
- `frontend/src/lib/forensicApi.ts`
- `frontend/src/lib/types/forensic.ts`
- `data/axiom/Magnet_AXIOM_10.2.0_All_Artifacts.csv`
- `backend/tests/test_axiom_artifact_tree_v32.py`

## Validation

- Python compile validation passed for the modified backend.
- V32 artifact/catalog regression suite passed.
- Modified TypeScript/TSX files passed TypeScript 5.8.3 syntax transpilation.
- The bundled AXIOM reference was parsed successfully and contains 3,590 artifact definitions, including 623 Windows definitions.

## Rebuild

From the project root:

```powershell
docker compose up -d --build api worker-disk worker-parse worker-rag-gpu worker-agent frontend
```

Then hard-refresh Chrome with `Ctrl+Shift+R`.
