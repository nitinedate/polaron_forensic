# Aetheris Mobile Full Extraction / ZIP / Case Layout / Progress Fix V19
Date: 2026-09-20

## Problems fixed

1. Case folders 01, 03, 04, 06, 09 (and 10) were not created by native Windows mobile jobs.
2. iOS short-path staging under `X:\ib` was left as a junction-backed authoritative payload.
3. Default mobile ZIP export could become metadata-only, producing a tiny ZIP even when the acquired payload was many GB.
4. Sealed iOS/Android payload was deliberately skipped from the ZIP by default.
5. The host export process killed export after three minutes, unsuitable for 100+ GB evidence.
6. iOS backup progress reached 100% before AFC/WhatsApp/media and packaging were complete; React converted this to 99.9%.
7. A previous iOS backup for the same UDID could be silently reused, producing stale evidence for a new acquisition.
8. A full ZIP failure could still leave the acquisition looking successful.
9. ZIP file inventory was capped/in-memory; large cases need a complete streaming index.

## V19 behavior

### Complete case skeleton
Every native Android/iOS collection now creates:

- 01_Authority
- 02_Original_Extraction
- 03_Working_Copy
- 04_PA_Case
- 05_Exports
- 06_Reports
- 07_Logs
- 08_Hashes
- 09_Review
- 10_Disclosure

Run-specific folders are also created for working copy, exports, reports, hashes and review.

### iOS staging
Windows short-path staging may still be used temporarily because Apple backup trees can exceed normal Windows path lengths. V19 changes its meaning:

- `X:\ib\...` is temporary staging only.
- Current-run iOS backup is physically committed into `02_Original_Extraction/<run>/ios_image/...`.
- AFC/house_arrest is physically moved/copied into `02_Original_Extraction/<run>/afc_media` and `house_arrest`.
- Successful commit removes the temporary AFC staging tree.
- Current acquisition no longer uses a persistent junction as the final evidence payload.
- Old iOS backup reuse is disabled by default. It is allowed only when `IOS_ALLOW_REUSE_BACKUP=1` is explicitly set.

### Full ZIP64 export
The primary `<run>.zip` now contains the complete *acquired* original payload by default:

- `02_Original_Extraction/...`
- acquisition logs
- hashes
- full streaming `file_index.jsonl`
- package metadata

ZIP64 is enabled. The prior 4 GiB metadata-only downgrade is removed.

A metadata-only export is possible only when explicitly requested with `--metadata-only`.

The exporter checks free disk space before creating the full archive. It requires approximately the uncompressed acquired payload size plus a 2 GiB reserve on the export volume. It will fail rather than silently emit a tiny metadata ZIP.

After writing, V19 verifies the count and uncompressed byte total of `02_Original_Extraction/` entries in the ZIP against the source tree. The ZIP itself is SHA-256 hashed.

The Windows host export timeout is increased from 3 minutes to 24 hours by default. Override with `AETHERIS_EXPORT_TIMEOUT_MINUTES`.

### Progress
Progress is no longer treated as "iTunes backup percent = total collection percent".

- iOS backup callback maps to approximately 5-65% overall.
- Backup completed / AFC start advances to approximately 68-72%.
- AFC/WhatsApp/media runs as a separate phase instead of reporting 100/99.9%.
- Full ZIP packaging starts around 90% and advances according to bytes archived.
- ZIP hashing/verification is approximately 99.6%.
- 100% is reserved for actual completed collection/export.

React now labels the figure `Overall progress` instead of `Backup` and no longer converts 100 to 99.9.

### Important forensic limitation
"Complete ZIP" means 100% of the payload successfully acquired by Aetheris is inside the ZIP. It does NOT mean Advanced Logical can acquire every byte counted by iPhone Settings storage.

An iPhone reporting ~120 GB used can include encrypted/protected application data, system data, caches, APFS/file-system content unavailable to backup/AFC, optimized iCloud originals, deleted/unallocated data, and other content unavailable through an iTunes-style backup + AFC/house_arrest. Acquiring that material requires an actually available Full File System/physical/vendor advanced-access method; software must not claim it recovered data the device interface never supplied.

## Validation
Focused mobile regression tests: 63 passed.

The whole frontend production build still reports existing unrelated TypeScript/JSX environment errors in vulnerability dashboard sources; the V19 MobileAcquisitionPage edits are limited to progress calculation/labels.
