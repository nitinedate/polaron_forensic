# Aetheris Mobile Export — Four-File Layout (V22)

Date: 2026-09-22
Scope: what an acquisition writes into `05_Exports/<run>`.

## Requirement

Match the reference UFED-style layout (`vivo_V2403.pas`, `vivo_V2403.ufd`, `Vivo.ufdx`,
`vivo_V2403.zip` — the zip carrying everything). The run's export folder must contain
**only four files** and **no sub-folders**:

```
05_Exports/<run>/
  <run>.zip     full ZIP64 payload (02_Original_Extraction/ + readable_artifacts/ + 07_Logs/ + 08_Hashes/)
  <run>.ufd     thin sidecar (metadata + hash manifest)
  <run>.pas     thin sidecar (metadata + hash manifest)
  <run>.ufdx    XML index
```

## What was being created before (Image 2)

`readable_artifacts/` folder, 22 × `<run>.part-NNNNN.zip` shards, a 4 MB metadata-only
`<run>.zip`, `content_inventory.json`, `export_catalog.json` (plus `payload_shards.json`,
`FULL_ZIP_LOCATION.txt`, `PARTIAL_COLLECTION.json` in some runs).

## Changes

### Packager — `backend/app/services/mobile_acquire/export_packages.py`
- Default is **one full `<run>.zip`** (ZIP_STORED, ZIP64; DEFLATE-1 only when the volume is tight —
  the V20 space planner is unchanged). The zip now also carries `readable_artifacts/` (WhatsApp,
  SMS, camera-roll DBs materialised from the backup), so it is self-contained.
- Sharding is **opt-in**: `AETHERIS_EXPORT_SHARDS=1`, `use_shards=True`, or `export_cli --shards`.
- All sidecars go to the side-files dir — `07_Logs/<run>` (fallback: the run's log dir, then
  `05_Exports/.aetheris/<run>`): `export_catalog.json`, `payload_shards.json`,
  `FULL_ZIP_LOCATION.txt`. Legacy sidecars found beside the packages are moved there.
- `payload_shard_catalog_complete(dest, catalog_dir)` and `write_payload_shards(..., catalog_dir)` for
  resumable opt-in shard runs.
- Payload verification (file count + bytes) still runs against `02_Original_Extraction/` members.

### CLI — `export_cli.py`
- `content_inventory.json` is written/read in the side-files dir; a legacy copy beside the packages is
  moved. New `--shards` flag.

### Acquisition scripts
- `scripts/native_ios_job.ps1`, `scripts/native_mtp_job.ps1`: the second `readable_artifacts` copy is
  materialised into `03_Working_Copy/<run>` (the derived overlay) instead of `05_Exports/<run>`.
  `PARTIAL_COLLECTION.json` goes to `07_Logs/<run>`.
- `backend/app/services/mobile_acquire/orchestrator.py`: same redirection for the in-process path.
- `scripts/host-mobile-acquire.ps1` (`Get-ExportCatalogFromDisk`): reads the catalog from
  `07_Logs/<run>` first, then falls back to globbing the four packages.

### Analysis side (registration / extract)
- `mobile_segments.py`: `read_export_catalog()` looks in `07_Logs/<run>` → `.aetheris` → legacy
  location; `_dir_has_export_payload()` recognises the four-file layout (`<run>.zip` + any of
  `.ufdx/.ufd/.pas`). `case_export_segment_paths()` registers **only `<run>.zip`** — the thin
  `.ufd/.pas/.ufdx` are never treated as payload (they would otherwise pull extract into walking the
  junctioned phone tree).
- `extracted_disk._ensure_mobile_payload_zips`: late packaging (analysis pointed at a live folder) now
  writes the same four-file layout via `build_export_packages` instead of shards.
- `run_registry._export_packages_from_dir`: catalog lookup via the same candidates.

Old runs that already have shards keep working: shard discovery and the legacy catalog location are
still honoured.

## Tests

- `tests/test_case_export_registration.py::test_export_writes_exactly_four_files` — runs
  `export_cli` on a synthetic iOS run and asserts the folder is exactly `.zip/.ufd/.pas/.ufdx`,
  sidecars are in `07_Logs/<run>`, `readable_artifacts/` is inside the zip, and every case folder
  (`03_Working_Copy`, `02_Original_Extraction`, `05_Exports`, case root) registers the single zip.
- `tests/test_ios_usbmux.py` shard/deflate/alternate-volume tests updated to the new contract
  (shards via `use_shards=True`, sidecars in the side-files dir).
