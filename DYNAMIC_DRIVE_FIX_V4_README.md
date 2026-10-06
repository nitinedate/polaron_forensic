# Aetheris Dynamic Windows Drive Fix v4

## Problem fixed

Windows can read an evidence folder such as:

`G:\Ex.1 Darshan SSD 256`

but Docker Desktop may still create an apparently valid bind mount whose Linux
container view is empty. The decisive failure is a direct Docker probe where
`/probe` exists but `/probe/Ex.1 Darshan SSD 256` does not.

This is not a PostgreSQL, React path-normalization, or forensic parser problem.
The Windows drive has not been exposed to Docker with its actual contents.

## v4 design

v4 no longer assumes that `G:/ -> /host/g` is valid merely because Docker
accepted the mount command.

For every detected Windows drive letter A: through Z:, the host-side resolver:

1. Confirms the drive exists in Windows.
2. Tests the real selected child path in a disposable Docker container.
3. Tries Docker Desktop's direct Windows drive paths first.
4. If Docker exposes an empty/stale removable-drive mount, creates a WSL2 DrvFs
   bridge under `/mnt/wsl/aetheris-host-drives/<letter>`.
5. Tests that bridge through the same Docker local-volume mechanism used in the
   final Compose services.
6. Generates a read-only `/host/<letter>` mount for `api`, `worker-disk`,
   `worker-mobile`, and `worker-report`.
7. Recreates only those four forensic services when necessary.
8. Waits for API health and verifies the exact selected evidence path in all
   four services.
9. Only then lets React enter **Receiving segments**.

No evidence files are copied by the mount recovery. The container-side mount is
read-only. The WSL DrvFs bridge is requested read-only first. Some current WSL
build/filesystem combinations reject one or more read-only DrvFs option sets; v4
then falls back to a normal DrvFs backing bridge only after the read-only attempts
fail. The evidence mounts presented to `api`, `worker-disk`, `worker-mobile`, and
`worker-report` still remain `read_only: true`.

## Why an external Docker volume is used for WSL paths

The v4 resolver can return a Linux-daemon path such as:

`/mnt/wsl/aetheris-host-drives/g`

Compose itself is launched by Windows. To prevent Windows-side Compose path
normalization from changing that Linux path, v4 pre-creates a uniquely named
Docker local volume using `device=<verified Linux path>` and declares the volume
as `external: true` in the generated override. The resolver tests the exact
same local-volume mechanism before accepting a source.

## UI sequencing fix

Earlier builds could open the **Receiving segments** modal before the selected
folder had been proven readable in Docker. v4 gates both native folder selection
and the in-app browse/register path on exact Docker verification first.

If recovery fails, the UI now displays the actual host-side error instead of the
generic "Check Docker Desktop file sharing" message.

## Automatic operation

After one-time installation, `AetherisHostDriveAgent` starts with an immediate
refresh at Windows logon and then watches Windows drive letters every 30 seconds.
New letters such as G, H, I, J, K, L, M, N, etc. are picked up automatically.
The exact folder-selection path also performs an on-demand verification, so the
user does not have to wait for the watcher.

## Deployment

Extract this patch over the existing project, for example `F:\rag_new2`.
Do **not** remove Docker data volumes.

Run from PowerShell:

```powershell
cd F:\rag_new2
powershell.exe -NoProfile -ExecutionPolicy Bypass -File .\scripts\deploy-dynamic-drive-v4.ps1 -RequiredPath "G:\Ex.1 Darshan SSD 256"
```

The deployment script:

- finds the exact Compose file stack of the currently running API using Docker
  labels and JSON (no fragile Go-template with dotted label names),
- reinstalls a single HostDrive watcher,
- rebuilds/recreates only the React frontend,
- runs the same exact-path automatic mount recovery used by the app,
- does not tear down PostgreSQL/Redis/MinIO or remove data volumes.

## Expected successful result

The exact output depends on whether Docker Desktop can expose the drive directly.
For the reported external-drive failure, the expected recovery is similar to:

```text
PASS: G:\Ex.1 Darshan SSD 256
Mount mode: wsl-drvfs
Mount source: /mnt/wsl/aetheris-host-drives/g
WSL distro: Ubuntu
```

`docker-direct` is also a valid result if Docker Desktop itself begins exposing
the drive correctly.

## Independent end-to-end test

```powershell
cd F:\rag_new2
powershell.exe -NoProfile -ExecutionPolicy Bypass -File .\scripts\test-dynamic-drive-mounts.ps1 -RequiredPath "G:\Ex.1 Darshan SSD 256"
```

The test must pass the exact path in all four services:

```text
PASS api
PASS worker-disk
PASS worker-mobile
PASS worker-report
```

## WSL prerequisite

The fallback uses WSL DrvFs. Docker Desktop normally uses the WSL2 backend on
current Windows installations, but if no usable WSL distribution is available,
the resolver returns an explicit error rather than pretending the disk is
mounted. Check with:

```powershell
wsl --version
wsl --list --verbose
```

The resolver tries normal installed distributions first and `docker-desktop`
last. `AETHERIS_WSL_DISTRO` may be set to force a specific distribution.

## Files changed

- `scripts/resolve-docker-drive-source.ps1`
- `scripts/generate-drive-mounts.ps1`
- `scripts/refresh-drive-mounts-job.ps1`
- `scripts/host-drive-helper.ps1`
- `scripts/hostdrive-agent.ps1`
- `scripts/install-hostdrive-agent.ps1`
- `scripts/test-dynamic-drive-mounts.ps1`
- `scripts/deploy-dynamic-drive-v4.ps1`
- `frontend/src/components/forensic/HostEvidencePanel.tsx`
- `frontend/src/lib/hostDriveHelper.ts`
- host-evidence backend/proxy files and regression tests from the previous
  dynamic-drive patch are included so v4 is self-contained.
