# Polaron V39 — Server-side HDD/SSD/USB browser and 502 prevention

## Problem reproduced

The Job Detail page repeatedly called `/api/hostdrive/drives` and `/api/hostdrive/ensure-all`, while the HostDrive background watcher automatically remounted Docker whenever a Windows drive letter changed. The remount job recreated the forensic API container itself. The browser was polling the same API during that restart, producing repeated `502 Bad Gateway` responses. Because the evidence dialog depended on the API for drive discovery, the **Server drives** section could also be empty even though Windows could see the external HDD/SSD/pendrive.

## V39 behavior

1. **Server-drive discovery is independent of Docker mounts.** When the Enterprise Console is open on `localhost`, React asks the Windows HostDrive helper (`127.0.0.1:9876`) first for `/drives` and `/list-dir`. A remote examiner browser uses the authenticated forensic API, which proxies the helper on the forensic server.
2. The evidence dialog always contains a dedicated **Server drives — HDD / SSD / USB / network — process in place** browser, with Refresh, helper status, Start helper, drive-letter buttons, folder navigation, Up, and **Use this folder**.
3. Merely attaching a new disk is now **detection only**. Neither the helper presence watcher nor the HostDrive agent watcher automatically recreates Docker/API services.
4. Docker remount occurs only after the examiner chooses an exact server folder. That selected path is mounted/read-only and processed in place; no browser upload or duplicate source copy is made.
5. During that one explicit mount, Job Detail pauses ordinary API polling to prevent transient 502 request storms.
6. The exact browse registration path marks the UI as `mounting` before the helper starts the remount.
7. HostDrive helper version is bumped to **5.39**, forcing a stale Windows helper to restart when the update is deployed. The refresh-job version is **4.13**; the forensic remount now recreates only `api` and `worker-disk`, not report/agent workers.
8. The scheduled HostDrive watcher and Startup-folder fallback no longer start with `-RefreshNow`; the browser protocol starts/ensures the helper without remounting Docker.

## Expected flow

```
Attach external HDD / SSD / pendrive to forensic server
                    |
                    v
Windows HostDrive helper detects drive letter
                    |
                    v
Browse for evidence folder -> Server drives
                    |
             browse read-only
                    |
            select exact folder
                    |
                    v
Mount selected drive into forensic API/worker-disk (only if needed)
                    |
                    v
List/register E01 segments -> Virtual disk -> Extraction
```

No Download Agent is used for server-local evidence.

## Deployment requirement

After copying V39 files, restart/reinstall the Windows HostDrive agent once so any already-running V38 watcher process is replaced by the detection-only V39 watcher:

```powershell
powershell -ExecutionPolicy Bypass -File .\scripts\install-hostdrive-agent.ps1
powershell -ExecutionPolicy Bypass -File .\scripts\ensure-host-drive-helper.ps1 -ForceRestart
```

Then rebuild the frontend. If using the repository root Compose stack:

```powershell
docker compose up -d --build frontend
```

If using `scripts\start-stack.ps1`, restart the forensic/gateway stack with the normal project command after applying the patch.
