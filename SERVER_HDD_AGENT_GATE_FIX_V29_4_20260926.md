# Polaron V29.4 - Disk server-HDD agent-gate isolation fix

## Symptom
On a Disk Forensics job, the modal could show `iOS Agent` / `Android Agent` and a timeout such as `Download Agent gate could not be opened safely`, even though the evidence HDD/SSD/USB was attached to the forensic server and visible in the zero-copy server evidence browser.

## Root causes
1. The pipeline modal used the global agent array and hard-coded step indexes 0/1. Because iOS and Android are the first global entries, Disk registration errors were displayed as phone-agent failures.
2. A folder selected through the office/server HostDrive path could, after a resolution/mount miss, silently fall back to browser upload when browser File objects happened to be present. That violated the zero-copy server-evidence rule and opened the Download Agent gate.
3. The generic timeout message still told the user to start the legacy root `docker compose` API/frontend stack, which is misleading for the current gateway + isolated product backends.

## V29.4 behavior

### Disk pipeline modal
Disk jobs now use a product-specific visible step list. They never display iOS/Android Agent cards.

Disk registration order begins with:
- Drive mount
- Download (only for explicit client upload)
- List folder
- Get segments
- Virtual disk
- Extraction
- Materialize
- OCR enrich
- Parse forensic files
- RAG / graph / inventory stages

Mobile jobs still use their platform owner and remain isolated from Disk.

### Server evidence is fail-closed zero-copy
If a selection originated from the forensic server / office HostDrive source, a mount or path-resolution failure now stops with a server-drive error. It never falls back to `uploadClientFiles()` and never opens `begin-client-upload`.

The examiner must refresh server drive mounts and retry. This prevents duplicate E01/EWF/RAW source files on the server.

### Client evidence remains explicit
Only the explicit `Upload from client computer...` path may invoke Download Agent. The V27 complete-manifest hold still applies: no extraction/parse/OCR/RAG/report until every client segment is staged and verified.

### Retry behavior
Retry is now based on the actual step ID rather than numeric indexes. A Download failure reopens client selection. Drive/List/Get-segments failures retry the server evidence path. Processing failures resume the processing pipeline.

### Timeout copy
Timeouts now say to check the Enterprise Console gateway and selected product backend rather than instructing the user to start the legacy root stack.

## Validation
- 93 relevant Disk/Mobile/HostDrive/platform isolation tests passed.
- 15 focused V29.4 + V27 residency tests passed.
- All six changed TS/TSX files passed TypeScript 5.8.3 ES2020 syntax transpilation.
- Full npm dependency installation/typecheck could not be executed in this sandbox because the npm cache does not contain all project dependencies and outbound package installation is unavailable.
