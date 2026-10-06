# Aetheris Mobile Case-Export Registration + Non-Blocking List Folder — V21

Date: 2026-09-22
Scope: registering an acquired iPhone/Android run for analysis, List folder performance, API responsiveness.

## Problem reproduced

Job page (Disk Jobs → Job Detail) showed, on the *Android Agent* step of a finished iPhone job:

```
No registerable evidence found at the selected location. Folder listing found 0 item(s)
(0 segment-like). Confirm the folder on the office forensic server contains files ...
```

with `POST /api/jobs/…/evidence/ingest-path → 400`, an `Uncaught (in promise)` from
`registerHostPath`, and several `GET /api/jobs/… → 502 Bad Gateway`.

The export folder itself was fine (Image 2): `05_Exports/<run>/` holds `readable_artifacts/`,
22 × `~4 GB .part-NNNNN.zip` payload shards, the 4 MB metadata `.zip`, `.pas/.ufd/.ufdx`
companions, `content_inventory.json` and `export_catalog.json`. Nothing was wrong with the
directory structure — the *wrong folder* was being registered, and the listing was blocking.

## Root causes

1. **Analysis was pointed at `03_Working_Copy/<run>`** (`MobileAcquisitionPage.startAnalysis`
   used `paths.working` first). `native_ios_job.ps1` creates that folder empty (V20 sealed
   original + derived overlay model). `_collect_segment_files` with `source_type="disk"` only
   looked at the folder itself → no files.
2. **`source_type` came from panel state**, so after a page reload / missing router state a phone
   job was registered as `"disk"`, which skipped the mobile export lookup entirely. The
   `payload zip` lookup that *did* exist only ran for `"mobile"`.
3. **Misleading error text**: with `skip_folder_list=True` the message hard-coded
   "Folder listing found 0 item(s)" even though List folder had just succeeded.
4. **Blocking listing loops**: `POST /jobs` (create) ran `register_segments` → full directory
   walk *inside the request*; `list-folder`, `process` (`_queue_disk_build → ensure_folder_listed`)
   and the agent huddle did the same. A 0-item listing never satisfies `listing_complete`, so every
   poll re-walked the tree. On a drvfs bind mount a phone tree takes hours; the browser gave up at
   120 s, the API thread stayed busy, and the gateway answered 502. "List folder 5:36:04" in the UI.
5. Unhandled promise from the auto-register effect on the job page; it also re-fired on an
   already-finished job.

## Fixes

### Backend

- `services/mobile_segments.py`
  - `locate_case_export_dir()`, `case_export_payload()`, `case_export_segment_paths()`:
    resolve **any** case-layout folder (`02_Original_Extraction/<run>`, `03_Working_Copy/<run>`,
    `05_Exports/<run>`, `05_Exports`, case root) to its export run and read
    **`export_catalog.json` as the authority** (`payload_shards`, `packages`), with a glob
    fallback (`*.part-NNNNN.zip`). Windows paths in the catalog are remapped to the container
    mount. Shards are returned in part order; the 4 MB metadata zip is excluded when shards exist;
    `.pas/.ufd/.ufdx` companions are only registered when there is no shard set.
  - `list_payload_zip_archives()` uses the same fast path first, so extract/virtual-disk keep
    reading exactly the shard set.
- `services/host_evidence.py`
  - `_collect_segment_files()` tries the case-export fast path for **both** `disk` and `mobile`.
  - `_walk_folder_entries()`: shallow listing (export folder top level only) for case runs — the
    junctioned phone tree is never walked by List folder. Deep walks now have a wall-clock cap
    (`LIST_FOLDER_MAX_SECONDS`, default 900 s) and mark the listing truncated instead of running
    for hours.
  - `register_segments()`: accurate diagnostics — uses the last real listing counts from
    `disk_build_logs`, and when the folder maps to an export run that has no payload yet it says
    so ("wait for 05_Exports to finish, then Try again").
  - `ensure_folder_listed()`: lists inline only when `folder_lists_fast()`; otherwise starts a
    background listing (or returns if one is already running). No poll ever blocks on a walk.
- `services/folder_listing_jobs.py` (new): one daemon thread per job with its own
  `firm_session`; results kept in memory for polling.
- `routers/jobs.py`
  - `POST /jobs`: no synchronous registration — persists the evidence folder only.
  - `POST /jobs/{id}/evidence/list-folder`: inline for fast folders, otherwise
    `{"status": "running"}`; new `GET /jobs/{id}/evidence/list-folder/status`.
  - `POST /jobs/{id}/evidence/ingest-path`: coerces `source_type` to `"mobile"` for phone jobs.
- `config.py` / `.env.example`: `LIST_FOLDER_MAX_SECONDS`.

### Frontend

- `MobileAcquisitionPage.startAnalysis`: prefill `paths.exports` → `working` → `original`.
- `JobDetailPage`: auto-register only while the job is idle and has no segments; promise
  rejection handled (no more `Uncaught (in promise)`).
- `HostEvidencePanel`: polls `list-folder/status` while a background walk runs (progress shown in
  the Receiving-segments modal); `forensicApi.listHostFolderStatus` + `HostFolderListing` type.

## Tests

`backend/tests/test_case_export_registration.py` (10 cases) reproduces the exact layout from the
screenshot (22 shards + companions + catalog) and asserts registration from every case folder,
shallow listing, companions-only fallback, and unchanged behaviour for plain E01 folders.

Pre-existing failures in `test_mobile_segments.py::test_is_disk_image_filename_mobile` and four
`test_dynamic_drive_compose.py` cases are unrelated and fail identically before this change.

## Operator notes

- No data migration. Restart `api`, `worker-disk`, `worker-mobile` after deploying.
- For the job in the screenshot: open the job, **Try again** — the persisted folder
  (`03_Working_Copy/<run>`) now resolves to the 22 shards in `05_Exports/<run>`.
