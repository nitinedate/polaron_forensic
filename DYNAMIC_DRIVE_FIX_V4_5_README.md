# Aetheris Dynamic Drive Hotfix v4.5

## What v4.5 fixes

The v4.4 refresh job completed successfully and reported `mode=docker-direct`, which means the selected Windows evidence path had already been mounted and verified by the production refresh path. The later end-to-end validator failed only in its redundant final probe with:

`NameError: name 'utf' is not defined`

That error is caused by Windows PowerShell 5.1 native-process quoting. A multiline `python -c` argument containing `decode("utf-8")` can reach Python as `decode(utf-8)`.

v4.5 sends Python probe programs over stdin using `python -` instead of using multiline `python -c` arguments. This change is applied to both:

- `scripts/test-dynamic-drive-mounts.ps1`
- `scripts/refresh-drive-mounts-job.ps1`

No database, evidence, Redis, MinIO, or Docker volumes are changed.

## Apply

Extract this ZIP over the project root, e.g. `F:\rag_new2`.

Then run:

```powershell
cd F:\rag_new2
powershell.exe -NoProfile -ExecutionPolicy Bypass -File .\scripts\test-dynamic-drive-mounts.ps1 -RequiredPath "G:\Ex.1 Darshan SSD 256"
```

Expected final result:

```text
PASS api
PASS worker-disk
PASS worker-mobile
PASS worker-report
PASS: G:\Ex.1 Darshan SSD 256 is visible read-only to all forensic services.
```
