# Dynamic Windows Forensic Drive Mount Fix

## Problem fixed

The forensic UI could see a Windows path such as `G:\Ex.1 Darshan SSD 256`, but the API/worker containers only had the drive letters that were present when the containers were created. The old refresh code also assumed every real Docker Desktop Windows share had to appear as Linux `drvfs`/`9p`; current Docker Desktop may use other file-sharing backends. This caused a real drive to be reported as an "empty stub".

There were two additional project-level problems:

1. `docker-compose.drives.generated.yml` was loaded through Compose `include` even though it redefines `api`/worker services. Compose `include` is for importing non-conflicting resources; dynamic drive mounts need to be merged as an override with `-f`.
2. The old generated override repeated normal `/app`, `/app/data`, `/scripts`, and evidence mounts. Compose merges service volumes by target, so an override could accidentally replace a worker's normal data mount. The generated file now contains **only** `/host/<letter>` mounts.

## New behavior

- Detects all current Windows drive letters `A:` through `Z:`; no fixed G/H/I/J list.
- Uses CIM, PowerShell filesystem drives, and a direct A-Z fallback for newly attached USB/SSD/HDD media.
- The exact folder selected in the React UI is sent to the host helper as `required_path`.
- The helper verifies the path exists in Windows before Docker is touched.
- The generated Compose override uses read-only long bind syntax with `create_host_path: false`, preventing a missing Windows source from silently becoming an empty directory/stub.
- Only `api`, `worker-disk`, `worker-mobile`, and `worker-report` are recreated when a drive mount is missing or stale.
- After recreation, the job verifies both the `/host/<letter>` mount point and the exact selected folder inside Docker.
- Mount detection is filesystem-agnostic (VirtioFS, gRPC-FUSE, 9p/drvfs, etc.).
- A background HostDrive refresh already in progress is joined instead of failing the UI with HTTP 409.
- Selected paths containing spaces are quoted when the helper launches the background PowerShell job.
- The React UI does not start the List folder / Receiving segments pipeline modal until the exact Windows path has passed the Docker mount preflight.

## One-time deployment on Windows

From the project root in **PowerShell**:

```powershell
# 1. Regenerate the drive override from the drives present right now.
powershell -ExecutionPolicy Bypass -File .\scripts\generate-drive-mounts.ps1

# 2. Confirm Compose can merge the base model + dynamic drive override.
docker compose -f .\docker-compose.yml -f .\docker-compose.drives.generated.yml config --quiet

# 3. Recreate only services that require forensic drive access.
docker compose -f .\docker-compose.yml -f .\docker-compose.drives.generated.yml `
  up -d --no-deps --force-recreate api worker-disk worker-mobile worker-report

# 4. Reinstall/start the HostDrive watcher so later drive-letter changes are automatic.
powershell -ExecutionPolicy Bypass -File .\scripts\install-hostdrive-agent.ps1
```

Normal project startup scripts (`scripts\startup.ps1`, `scripts\start-server.ps1`, and `scripts\start-stack.ps1`) already regenerate and merge `docker-compose.drives.generated.yml`.

## End-to-end test

Use the exact folder visible in Windows Explorer. Example matching the reported case:

```powershell
powershell -ExecutionPolicy Bypass -File .\scripts\test-dynamic-drive-mounts.ps1 `
  -RequiredPath "G:\Ex.1 Darshan SSD 256"
```

The script performs four checks:

1. The exact path exists on Windows.
2. The dynamic mount refresh succeeds.
3. `docker compose ... config --quiet` succeeds.
4. The exact path is readable inside `api`, `worker-disk`, `worker-mobile`, and `worker-report`.

Expected final line:

```text
PASS: G:\Ex.1 Darshan SSD 256 is dynamically mounted read-only and visible to all forensic services.
```

The same command works with `H:`, `I:`, `J:`, `K:`, `L:`, `M:`, `N:` or another available drive letter.

## If Docker Desktop rejects the drive

If Windows sees the folder but the test says Docker cannot see it, open Docker Desktop and confirm the drive/folder is allowed under **Settings > Resources > File sharing**, then Apply/Restart Docker Desktop and rerun the test. This is a Docker Desktop sharing/permission boundary; an already-running container cannot be given a new bind mount without recreation.

## Files changed

- `docker-compose.yml`
- `docker-compose.https.yml`
- `docker-compose.drives.generated.yml`
- `scripts/generate-drive-mounts.ps1`
- `scripts/refresh-drive-mounts-job.ps1`
- `scripts/host-drive-helper.ps1`
- `scripts/hostdrive-agent.ps1`
- `scripts/test-dynamic-drive-mounts.ps1` (new)
- `backend/app/services/host_evidence.py`
- `backend/app/services/hostdrive_agent.py`
- `backend/app/routers/hostdrive.py`
- `frontend/src/lib/hostDriveHelper.ts`
- `frontend/src/components/forensic/HostEvidencePanel.tsx`
- focused tests under `backend/tests/`
- `DYNAMIC_DRIVE_FIX_TEST_RESULTS.txt` (validation report)
