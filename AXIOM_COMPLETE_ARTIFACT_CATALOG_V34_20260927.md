# Polaron V34 - Complete AXIOM Artifact Catalog and Counts

## Problem
The Disk Artifacts tree only displayed AXIOM definitions whose persisted count was greater than zero. This hid legitimate AXIOM artifact names such as **Pictures** and **Videos** whenever their count had not yet been calculated or the evidence did not contain that artifact.

A second issue caused missing counts on older jobs: the artifact inventory reused `artifact_scope`, even though that setting is only intended to control what is included in the report. Saving a limited report scope therefore prevented the remaining AXIOM catalog definitions from ever being counted.

A third issue could mark the AXIOM inventory complete too early because legacy `RPT-*` result rows were included in the completed-row total even when those IDs were not part of the current official platform catalog.

## V34 behavior

1. The Artifact Explorer always returns every official AXIOM 10.2 definition for the detected evidence platform.
2. Definitions with no evidence are retained in the tree with count `0`.
3. Report scope no longer limits artifact discovery/counting. It only controls report inclusion.
4. Existing/old jobs automatically detect missing official catalog counts and queue only the missing inventory rows. No E01 copy, download, or disk re-extraction is required.
5. Inventory completion is measured only against artifact IDs in the current platform catalog, so stale legacy result rows cannot make the job appear complete early.
6. Legacy singular report labels are bridged to official names while an old job is being backfilled, including:
   - `Picture` -> `Pictures`
   - `Video` -> `Videos`
   - `Jump List` -> `Jump Lists`
   - `Logfile Analysis` -> `$LogFile Analysis`
   - `Remote Desktop Protocol (RDP)` -> `Remote Desktop Protocol`
   - `Your Phone Device` -> `Your Phone Devices`
   - `Installed Programs (Non-Microsoft)` -> `Installed Programs`
7. The UI states how many AXIOM artifact definitions are loaded, how many currently have non-zero evidence counts, and explicitly notes that zero-count definitions remain visible.

## Expected Windows behavior
The bundled Magnet AXIOM 10.2 reference contains more than 600 Windows definitions (623 in the bundled reference). The tree therefore includes all definitions such as:

- Media -> Audio
- Media -> Pictures
- Media -> Videos
- Media -> Carved Video
- Documents -> Microsoft Word Documents
- Documents -> Microsoft Excel Documents
- Documents -> Microsoft PowerPoint Documents
- Documents -> PDF Documents
- Operating System -> LNK Files
- Operating System -> Jump Lists
- Web Related browser artifacts
- Email and Calendar artifacts
- Connected Devices artifacts
- Application Usage artifacts
- Encryption and Credentials artifacts
- Communication artifacts
- and every other definition present in the bundled platform catalog.

If a definition is not found in the evidence, it still appears with `0` rather than disappearing.

## Important counting rule
The physical evidence-file total (for example 90,489 files) is not the same as the sum of AXIOM artifact record counts. A single source database can emit many artifact records, and some artifact domains overlap. Polaron therefore keeps the evidence-file total and per-definition AXIOM counts separate.
