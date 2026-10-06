# Aetheris Dynamic Drive Fix v4.3

## Fix in this hotfix

This hotfix fixes the Windows PowerShell error:

`resolve-docker-drive-source.ps1 : Argument types do not match`

The root cause was use of `New-Object System.Collections.Generic.List[...]` followed by PowerShell array-subexpression conversion such as `@($list)`. On Windows PowerShell 5.1 this can throw `System.ArgumentException: Argument types do not match`.

The dynamic drive resolver and refresh job now use plain PowerShell arrays/hashtables for these small collections. This preserves the existing direct-Docker and automatic WSL/DrvFs recovery logic while avoiding the PowerShell 5.1 binder bug.

## Files changed

- `scripts/resolve-docker-drive-source.ps1`
- `scripts/refresh-drive-mounts-job.ps1`

## Apply

Extract this ZIP over the existing project root (`F:\rag_new2`) and overwrite files.

No database, evidence, MinIO, Redis, PostgreSQL, or Docker volume data is touched.

Do not run `docker compose down -v`.

## Validate

Run:

```powershell
cd F:\rag_new2
powershell.exe -NoProfile -ExecutionPolicy Bypass -File .\scripts\test-dynamic-drive-mounts.ps1 -RequiredPath "G:\Ex.1 Darshan SSD 256"
```

The old `Argument types do not match` failure should be gone. The test will then continue into direct-Docker/WSL recovery and report the real mount result.
