# Aetheris Mobile Storage + Full ZIP Fix V20

Date: 2026-09-21
Scope: iOS Advanced Logical acquisition, staging, full evidence ZIP64 export, storage preflight, progress reporting, and partial-collection handling.

## Problem reproduced

The examiner UI reported:

- `Insufficient free space for full ZIP64 export: payload=91496307407 free=87763783680 ...`
- `Shared photos and WhatsApp container files were collected, but the iTunes-style backup did not finish.`

The old V19 full-ZIP path required enough free space for a second, uncompressed copy of the whole acquired payload. In the reported run the acquired payload was about 85.2 GiB while the export volume had about 81.7 GiB free, so the requested uncompressed second copy could not physically fit.

The iOS backup helper also used a fixed minimum staging threshold. A large phone could therefore pass the initial check and run out of space late in the acquisition. The native job could then try to package AFC-only data even though the iTunes-style backup was incomplete, producing a confusing second error.

## Fixes in V20

### 1. Device-aware iOS storage preflight

`scripts/ios_usbmux_backup.py` and `scripts/host-mobile-acquire.ps1` now query `com.apple.disk_usage` where available and size backup staging from the phone's current used data rather than a fixed 80 GiB rule.

Required free space is conservatively calculated as:

`max(80 GiB, device_used_bytes + max(12 GiB, 10% of device_used_bytes))`

A ~120 GiB used iPhone therefore requires roughly 132 GiB on one staging volume before the iTunes-style backup starts. If no volume fits, acquisition fails immediately with a clear storage error instead of filling a drive after hours of collection.

Environment overrides:

- `IOS_BACKUP_MIN_FREE_GB`
- `IOS_BACKUP_RESERVE_GB`
- `IOS_BACKUP_REQUIRED_FREE_BYTES`

### 2. `X:\ib` is temporary only

Short `X:\ib\...` paths are retained only because they avoid Windows long-path problems during iOS backup/AFC collection.

After a successful stage:

- If the case and staging paths are on the same volume, the data is renamed/moved into `02_Original_Extraction`.
- If they are on different volumes, V20 avoids duplicating 100+ GiB. The temporary path is renamed on the same volume into `X:\Aetheris_Mobile_Payloads\...`, and the case folder receives a Windows junction plus `EXTERNAL_IOS_PAYLOAD.json` / `EXTERNAL_AFC_PAYLOAD.json` provenance metadata.
- Hashing, content inventory, case export, and ZIP generation explicitly follow those evidence junctions.

This means the final evidence no longer remains in the temporary `X:\ib` namespace.

### 3. Full ZIP can use another volume automatically

`backend/app/services/mobile_acquire/export_packages.py` now checks:

1. the requested case export directory,
2. `AETHERIS_EXPORT_ROOT` when configured,
3. other connected Windows filesystem volumes.

When the case volume cannot hold the complete ZIP, the exporter can place the full ZIP on another suitable volume. The normal `05_Exports/<run>` folder gets `FULL_ZIP_LOCATION.txt`, and the API result exposes the actual ZIP path.

Optional explicit export volume example:

`AETHERIS_EXPORT_ROOT=G:\Aetheris_Exports`

### 4. Fast DEFLATE fallback instead of requiring a raw second copy

When no volume can hold an uncompressed/stored ZIP, V20 samples the acquired evidence to estimate fast DEFLATE compression. If the estimated compressed archive plus safety reserve fits, the full payload is written with ZIP64 + DEFLATE level 1.

The payload is never silently downgraded to a 2-3 KB metadata-only ZIP.

If no connected volume can safely hold the complete archive even after estimated compression, the job fails early and cleanly. This is a physical storage constraint and cannot be bypassed without providing more storage.

Environment setting:

- `AETHERIS_EXPORT_RESERVE_GB` (default 1 GiB; minimum 256 MiB)

### 5. Live free-space guard while ZIP is being written

The ZIP writer rechecks remaining free space during packaging. If the selected volume falls below the safety reserve, the incomplete ZIP is deleted and a concise storage error is returned.

### 6. Complete archive verification

After writing the ZIP, Aetheris compares:

- archived evidence file count versus source file count
- total uncompressed archived bytes versus source bytes

The acquisition is not marked complete if those values do not match.

### 7. No full ZIP from an incomplete iOS backup

`scripts/native_ios_job.ps1` now creates the full evidence ZIP only when the iTunes-style backup has actually completed (Manifest.db/Manifest.plist is valid).

If AFC/WhatsApp shared data exists but the backup is incomplete, the data remains preserved and `PARTIAL_COLLECTION.json` is created. It is not mislabeled as a complete evidence package.

For a storage-preflight backup failure, V20 skips AFC rather than spending additional hours collecting a partial side channel that cannot result in a complete Advanced Logical package.

### 8. Progress reporting fixed

`export_cli.py` no longer forces every export event to 100%.

Packaging emits real staged progress in the 90-99.x range. Only an explicit `stage=complete` event reaches 100%.

The iOS backup/AFC workflow also keeps acquisition phases distinct, preventing the old artificial `99.9%` while data is still being copied.

### 9. Working-copy storage pressure reduced

When there is not enough free space to make another full physical working copy, `03_Working_Copy/<run>` still exists but contains `WORKING_COPY_NOT_MATERIALIZED.json`. Processing uses the sealed original plus derived analysis outputs instead of consuming another phone-sized copy.

This avoids needing three simultaneous copies of a 100+ GiB acquisition just to continue analysis.

### 10. Cleaner UI errors

Export storage failures now return concise JSON error codes rather than a Python traceback. The React host-drive helper maps the new error codes to examiner-readable storage instructions.

Primary codes include:

- `mobile_export_insufficient_space`
- `mobile_export_io_error`
- `ios_backup_not_enough_disk_space`
- `ios_afc_not_enough_disk_space`

## Tests

Focused V20 mobile regression suite:

- 58 passed
- 1 deselected known baseline test (`test_live_device_external_tool_required`)

That deselected test also fails unchanged in the V19 baseline because the current capability implementation returns `DEVICE_UNLOCK_REQUIRED` while the old test expects `EXTERNAL_TOOL_REQUIRED`; it is unrelated to this storage/export patch.

`backend/tests/test_ios_usbmux.py`: 31 passed, including new tests for:

- 120 GiB used-device backup sizing
- compressed ZIP when raw copy cannot fit
- automatic alternate export volume
- export progress not reaching 100 before completion
- storage errors returned as JSON instead of tracebacks

Python modules modified by this patch pass `py_compile`.

Frontend full TypeScript/lint validation could not be used in this sandbox because the extracted project's frontend dependency tree cannot resolve its existing React/type packages; the changed helper is a small error-message mapping and the failure is unrelated to this patch.

## Deployment / retry

1. Deploy the V20 project or patch.
2. Stop any old V19 iOS acquisition process.
3. Do not manually delete already acquired evidence unless it has been independently verified/backed up.
4. Ensure at least one local volume has sufficient free space for the device-aware staging requirement.
5. Prefer a different export volume when the acquisition volume is tight, for example:

   `setx AETHERIS_EXPORT_ROOT "G:\Aetheris_Exports"`

6. Restart the application/worker so environment changes and the new scripts are loaded.
7. Start a new Advanced Logical acquisition.
8. Confirm UI storage preflight before collection begins.
9. At completion verify `export_packages.zip`, SHA-256, and `export_catalog.json`. If the ZIP was placed on an alternate volume, `05_Exports/<run>/FULL_ZIP_LOCATION.txt` records the exact path.

## Forensic limitation

A phone showing ~120 GiB used in Settings does not imply an Advanced Logical backup will expose all 120 GiB. iCloud-optimized originals, applications excluded from backup, protected containers, deleted/unallocated APFS content, and other data not exposed through Apple's backup/AFC interfaces require a different acquisition capability. V20 guarantees that all data successfully acquired by Aetheris is preserved and included in the complete evidence ZIP; it does not claim access to bytes the acquisition method cannot lawfully/technically expose.
