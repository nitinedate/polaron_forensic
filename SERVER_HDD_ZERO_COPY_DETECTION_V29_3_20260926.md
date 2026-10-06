# Polaron V29.3 — Server HDD zero-copy detection fix

## Problem reproduced
On Disk Job Detail, `HostEvidencePanel` was rendered with both `embedded` and `autoProcess` enabled. The component entered its compact `fullyAutomated` branch and returned before rendering the server evidence browser. The only visible action was the client/browser folder picker, which uploads evidence to the server.

A second issue prevented automatic discovery from healing newly attached server disks: server drive synchronization was gated by the browser computer's localhost HostDrive helper cache, and explicit refresh did not request `sync_attached=true`. Thus Docker could keep older C:/D:/... mounts while a newly attached HDD/SSD/USB letter remained absent.

## V29.3 behavior

### Server / network / removable evidence
- Disk Job Detail always shows the **Server evidence browser — zero-copy** for Disk jobs, even when embedded auto-processing is enabled.
- Server-side drive discovery is obtained from `/api/hostdrive` first and is not gated by a remote examiner browser's localhost helper.
- Newly attached Windows drive letters are synchronized using `sync_attached=true`.
- The selected server evidence path is mounted read-only and registered in place.
- E01/E02/... segments are not uploaded, copied to staging, or duplicated in MinIO before extraction.
- The client-upload cleanup path never deletes the server source.

### Client evidence
- The client folder picker remains available as a separate path.
- Client evidence is uploaded to staging and remains subject to the V27 full-manifest hold gate.

### Dynamic drive workers
The Windows refresh job now includes `worker-parse` in the forensic remount service set, so extraction and parse workers see the same read-only server evidence path after a removable drive refresh.

## UI changes
Disk Job Detail now presents a server-first prompt:

`Server / network / removable HDD, SSD or USB — process in place`

with a **Detect server drives** action. The client upload panel is explicitly labeled as the fallback for evidence that is not attached to the forensic server.

## Automatic detection flow
1. Query the office/server HostDrive API.
2. Merge actual server letters and volume metadata into the evidence browser.
3. If Windows sees a letter that the forensic container cannot read, request a read-only dynamic remount with `sync_attached=true`.
4. Reload the browser after the remount.
5. Poll every 30 seconds for newly attached server drives while the job is waiting for evidence.

A failed volume does not trigger endless container restarts: each unchanged drive inventory gets one automatic remount attempt; the examiner can explicitly press **Refresh drive mounts** to retry.

## Server diagnostic command
From the project root on the forensic Windows server:

```powershell
powershell.exe -NoProfile -ExecutionPolicy Bypass -File .\scripts\check-server-evidence-drives.ps1
```

If the HostDrive helper is offline:

```powershell
powershell.exe -NoProfile -ExecutionPolicy Bypass -File .\scripts\ensure-host-drive-helper.ps1
powershell.exe -NoProfile -ExecutionPolicy Bypass -File .\scripts\hostdrive-agent.ps1 -RefreshNow -Once
```

To validate an exact path, for example `G:\Case01`:

```powershell
powershell.exe -NoProfile -ExecutionPolicy Bypass -File .\scripts\test-dynamic-drive-mounts.ps1 -RequiredPath "G:\Case01"
```

## Validation
- 58 targeted server-drive / V27 residency / drive-mount / HostDrive / path tests passed.
- The two changed TSX files passed TypeScript 5.8.3 syntax checking against ES2020.
- Full `npm ci` / Vite build could not be completed in the sandbox because package installation timed out; no TypeScript syntax errors were found in the changed files.
