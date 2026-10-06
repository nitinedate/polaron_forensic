# Polaron V29.5 — Server source mode and removable-drive mount repair

## What this fixes

V29.5 makes the evidence transport boundary explicit:

- **Server-accessible source**: Windows server disk, server-attached HDD/SSD/USB/pendrive, or a mapped network drive visible to the forensic server. The application registers and processes the evidence in place. There is no browser download/upload activity and no duplicate source image.
- **Client source**: evidence chosen through the browser file/folder picker on a different examiner/client computer. The client transfer screen is shown, up to five files are transferred concurrently, and the forensic pipeline remains held until the entire declared segment set is present and verified.

The selected source mode, not the browser's network address, decides the transport path. Jobs persist `source_origin=server_accessible, transport_mode=zero_copy` for server sources and `source_origin=client_browser, transport_mode=staged_upload` for client sources. Browser File APIs intentionally do not reveal a trustworthy original local path, so the explicit client-upload control is the only path that can invoke Download Agent.

## G: stale/missing mount root cause

A newly inserted removable disk can be visible to Windows as `G:` while an existing Docker container still has an old or empty `/host/g` bind. The old first-pass drive generator could discard `G:` when a whole-root `G:/` Docker bind probe failed, which prevented the later exact-path recovery from ever running.

V29.5 fixes this by retaining the examiner-selected drive for source resolution. It first attempts a narrow read-only bind of the exact selected evidence folder. For a selected E01 file, its parent folder is mounted so E02/E03/... siblings remain accessible. If direct Docker Desktop sharing is unavailable, the existing WSL/DrvFs fallback remains available.

No evidence bytes are copied by either recovery mode.

## Exact-path authority

A mounted `/host/g` root is no longer treated as proof that the selected evidence is ready. The exact selected path must be readable from API, disk worker, parse worker, report worker, and agent worker before the pipeline is released.

This is important when removable media is swapped while Docker keeps an older bind alive.

## UI behavior

When a server source is selected:

- any stale browser upload session is cleared;
- **Upload/Download Activity** is hidden;
- **Download** is removed from the Disk processing pipeline;
- only server stages such as Drive mount, List folder, Get segments, Virtual disk, Extraction, Parse, OCR and RAG remain.

When the explicit **Upload from client computer** control is used, Download Agent and Upload Activity are shown normally.

## Manual repair / verification

After applying V29.5, the UI performs this recovery automatically. To validate a path manually on the Windows forensic server:

```powershell
powershell.exe -NoProfile -ExecutionPolicy Bypass `
  -File .\scripts\repair-server-evidence-path.ps1 `
  -RequiredPath "G:\2026SEP-11\E-Drive\data\Image of Ex-5 Histotechlab1 512GB.E01"
```

A successful result reports a mount mode such as `docker-exact-path`, `docker-direct`, or `wsl-compose`. The selected evidence remains on its original disk and is mounted read-only.

## Validation

- V29.5 server-source, HostDrive, client-intake and residency regression set: 59 passed.
- Changed Python modules compile successfully.
- Six changed TypeScript/TSX files pass TypeScript 5.8.3 ES2020 syntax transpilation.
- The broader legacy dynamic-drive test module contains five assertions that already fail on the V29.4 baseline because they describe older implementation strings/runtime sample YAML; these are not V29.5 regressions.
