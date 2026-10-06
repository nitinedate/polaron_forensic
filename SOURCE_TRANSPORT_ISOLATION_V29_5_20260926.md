# Polaron V29.5 — Server vs Client Evidence Transport Isolation

## Problem
Disk Job Detail could still display a persisted **Upload Activity / Download Agent** panel even while the examiner was using the server-side HostDrive browser. The Disk pipeline also always contained a `Download` stage even though server-attached HDD/SSD/USB/network evidence is processed in place.

This mixed two different acquisition contracts:

1. **Server-accessible evidence** — HDD/SSD/USB or server/network share visible to the forensic server. Bytes stay at the original path and are processed zero-copy.
2. **Client-browser evidence** — images exist only on the examiner/client computer. Files must first transfer to server staging; all downstream processing remains held until the full declared set is received and verified.

## V29.5 source transport contract
The transport decision is based on the acquisition channel, not on the browser URL or IP address.

### Server channel
Selecting/opening a drive/folder through **Server evidence browser — zero-copy** marks the active transport as `server` immediately.

Backend metadata after registration:

```json
{
  "intake": "server_local",
  "source_residency": "server_local",
  "source_origin": "server_attached_or_mapped | server_network | server_path",
  "transfer_required": false,
  "cleanup_policy": "never_delete_source"
}
```

Behavior:
- no browser upload;
- no Download Agent;
- no staging copy of E01/E02/...;
- no MinIO copy of raw source segments before extraction;
- original source is never auto-deleted;
- server drive mount/list/register logs go to the normal extraction/activity log.

### Client channel
Only the explicit **Upload from client computer** path marks the transport as `client`.

Backend metadata:

```json
{
  "intake": "browser_upload",
  "source_residency": "client_uploaded_to_server",
  "source_origin": "client_browser",
  "transfer_required": true,
  "cleanup_policy": "delete_after_pipeline_success"
}
```

Behavior:
- Download Agent appears;
- up to five files transfer concurrently;
- extraction / parse / OCR / RAG / report remain held until all declared files are fully received and verified;
- client staging is deleted only after successful terminal processing.

## UI changes
- `Upload Activity` is now **Client transfer activity**.
- The client transfer panel is hidden for server transport, even if stale client-transfer messages exist in browser `sessionStorage`.
- Selecting a server drive clears stale inactive client transfer UI state.
- Disk Processing Pipeline omits `Download` by default/server mode.
- `Download` appears only when the job has explicitly entered `browser_upload` / client transport.
- Client transport omits the server Drive Mount stage.
- Disk evidence card heading is now **Select server evidence or upload from client**.

## Why browser IP is not used
A browser opened on `localhost`, LAN IP, VPN, or public hostname does not reliably tell where the evidence bytes live. A browser on the forensic server can still choose a client-mounted folder, and a remote workstation can operate the server-side HostDrive browser. Therefore V29.5 uses the selected acquisition channel as the authoritative classification:

- HostDrive/server browser => server zero-copy
- browser File/Directory picker => client transfer

This prevents accidental duplication and avoids false network-location inference.

## Validation
- 121 relevant Disk source-residency, Download Agent, HostDrive, Android/iOS isolation, semaphore and host-capacity tests passed.
- `backend/app/services/host_evidence.py` compiles cleanly.
- Changed TS/TSX files passed TypeScript 5.8.3 ES2020 syntax transpilation.

