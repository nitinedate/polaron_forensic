# Polaron V29.5 — Server/client evidence-origin routing and gateway build repair

Date: 2026-09-26

## Problem reproduced
A Disk job could correctly detect HDD/SSD/USB volumes in the **Server evidence browser — zero-copy** while the Job Detail page still displayed the old **Upload Activity / Download Agent** console. This mixed two mutually exclusive evidence transports:

- server-attached/network evidence, which must be processed in place; and
- browser/client evidence, which must be copied to server staging before processing.

Some V29.4 installations also had a partial frontend overlay, producing these gateway build errors:

- `TS2305`: `hasSelectedEvidence` imported but not exported by `orchestrationStages`.
- `TS2367`: stale/partially patched `HostEvidencePanel` source-type narrowing compared incompatible literal types.

## Authoritative routing rule
The application does **not** infer evidence residency from `localhost`, LAN IP, browser IP, DNS name, or subnet. Those signals are unreliable when administrators use RDP, reverse proxies, VPNs, NAT, or browse the console from the forensic server itself.

Residency is determined by the evidence-selection contract:

### Server evidence browser
Selecting a path through the server evidence browser means:

- `intake=server_local`
- `source_origin=forensic_server`
- `transport=in_place`
- `download_required=false`
- `source_residency=server_local`
- `cleanup_policy=never_delete_source`

Flow:

`detect server drive -> read-only Docker mount -> list folder -> register segment paths -> virtual disk/extract`

There is no browser upload, no source staging copy, no Download Agent, and no automatic deletion of the source HDD/SSD/USB/network evidence.

### Upload from client computer
The explicit client-upload control means:

- `intake=browser_upload`
- `source_origin=client_workstation`
- `transport=staged_upload`
- `download_required=true`
- `source_residency=client_uploaded_to_server`
- `cleanup_policy=delete_after_pipeline_success`

Flow:

`declare manifest -> upload max 5 concurrently -> verify every declared segment -> release pipeline -> process -> delete staging only after terminal success`

Extraction, parse, OCR, RAG, graph, enrichment, and reporting remain held until the complete client manifest is present and verified.

## UI isolation changes
- The right-hand transfer console is renamed **Client transfer activity**.
- It is rendered only for explicit/active client intake.
- Server evidence selection clears stale browser-upload session activity.
- Clicking a server drive/folder immediately establishes server intent and clears stale client-transfer UI before registration completes.
- A Disk job omits the Download stage unless the backend says the intake is client upload or a live explicit client transfer is underway.
- An explicit client upload temporarily inserts the Download step into the modal before the next job poll returns durable `browser_upload` metadata.
- Server mount/path failures remain fail-closed and never fall back to browser/client upload.
- Disk Job Detail copy now says **Select server evidence or upload from client** to make the two transports explicit.

## Build repair
- `orchestrationStages.ts` now exports `hasSelectedEvidence()` so a partially overlaid V29.4 `AgentPipelineBanner` cannot fail with TS2305.
- The V29.5 overlay contains the complete current `HostEvidencePanel.tsx`, removing the stale literal-narrowing state that produced TS2367 on partially patched installations.
- The V29.5 patch is a repair overlay containing complete critical frontend files, not only a textual unified diff.

## Validation
- 151 Disk/Mobile/source-residency/semaphore/artifact/theme regression scenarios passed.
- 41/41 LaptopScanner tests passed.
- Modified Python services compile successfully.
- Eight changed TypeScript/TSX files pass TypeScript 5.8.3 ES2020 syntax transpilation.
- Targeted semantic check reports no TS2305, TS2367, TS6133, or TS2550 regressions in the changed files. Full dependency-resolution `tsc -b` cannot be executed in this sandbox because the project npm dependencies are not installed here.
