# Aetheris Dynamic Drive v4.2 hotfix

This hotfix fixes the v4/v4.1 error:

`Drive generator returned no drive letters.`

## Root cause

`refresh-drive-mounts-job.ps1` invokes `generate-drive-mounts.ps1` directly and captures the PowerShell success/output stream. The generator printed `Letters: ...` using `Write-Host`. In Windows PowerShell 5.1, `Write-Host` is not the normal success/output stream, so the caller could receive no `Letters:` record even after `docker-compose.drives.generated.yml` was written correctly.

## Fix

1. `generate-drive-mounts.ps1` now emits the machine-readable `Letters:` record using `Write-Output`.
2. `refresh-drive-mounts-job.ps1` no longer depends only on console text. If the record is unavailable, it recovers the drive letters from the generated Compose `/host/<letter>` targets, which are the source of truth.

The fix keeps A: through Z: discovery and does not delete Docker volumes or evidence.

## Apply

Extract this ZIP over the existing project root (`F:\rag_new2`) and then run:

```powershell
powershell.exe -NoProfile -ExecutionPolicy Bypass -File .\scripts\test-dynamic-drive-mounts.ps1 -RequiredPath "G:\Ex.1 Darshan SSD 256"
```

No frontend rebuild is required for v4.2 if v4.1 was already deployed successfully through the frontend build stage.
