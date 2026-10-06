# Aetheris report V4 — Annexure row continuity + forensic objective evidence correction

Date: 2026-09-16

## 1. Annexure serial numbers 1,2 then 8: root cause

The database/backend did not discard rows 3–7. `gather_annexure_structured()` creates the top-visited URL rows with a contiguous `enumerate(..., 1)` sequence.

The loss was visual. The React A4 paginator estimated a table row from the longest cell as though that cell had almost the full page width. On a five-column fixed-layout table the URL column is much narrower, so URLs wrap into many more physical lines. The paginator advanced its row offset as if rows 1–7 fit, while the fixed A4 page (`overflow: hidden`) clipped rows that extended below the printable body. The next page therefore began at row 8.

### Fix

- Estimate row height from the actual number of columns.
- Treat URL-like cells as narrower because they wrap heavily.
- Account for table title, note, header and continuation chrome.
- Advance the source offset only by rows actually emitted in the page chunk.
- Keep the existing full URL text; do not silently drop records to make a page fit.

Expected invariant: a 15-row preview renders serials `1..15` exactly once across continuation pages.

## 2. Why observations differed from the AXIOM reference report

The previous report path could confuse a raw parser/inventory total with the real-world fact requested by the objective. Examples:

- `USB Devices = N` is a count of raw USB-related rows, not necessarily N physical external drives.
- `Web Related Files = N` is not a cloud-service count, WhatsApp-transfer count, or malware/phishing URL count.
- total Documents/LNK/Jump List rows are not proof that a particular file was opened/copied/deleted.
- total email messages are not the number of email accounts.

The reference-report pattern is: **objective -> exact evidence questions -> classify -> deduplicate -> correlate -> answer -> limitation**.

## 3. Missing information now made explicit in Objective / Procedure

For the key data-leakage objectives the system now requires the following before Observation writing:

### User Accounts & Login Activity
- distinct account/user identity
- supported sign-in/session times
- success/failure and local/remote state where supported
- unusual/unauthorized conclusion only when case evidence supports it
- never use total Event Logs as login/user count

### File Access and Handling
- distinct relevant file identity
- exact supported action: open / modify / rename / copy / delete
- timestamp and user/application where supported
- organization relationship by content/OCR/hash/trusted metadata where available
- never turn total Documents/LNK/Jump List rows into a file-action finding

### USB and External Device Usage
- distinct physical removable/storage device
- model/friendly name + serial/stable identity + volume label
- first/last supported connection time
- exclude internal disk, hub, camera, Bluetooth and input interfaces from storage-device count
- require separate file-access/write evidence before saying data was transferred

### Malware, Phishing and Pornography URLs
- distinct classified URLs/indicators by category
- URL/domain and supported time
- distinguish visit vs download vs antivirus detection vs execution
- never use total Web Related Files as the classified-URL count

### Access to Cloud Storage Services
- distinct cloud services after URL/session deduplication
- browser/profile and access time
- access-only vs upload/download/sync state
- organization-related downloaded/synced files based on content/OCR/hash when available

### Connection of External Hard Disks
- distinct physical HDD/SSD identities after correlating USBSTOR/SetupAPI/volume/mount records
- model/serial/volume + times
- exclude non-storage and internal devices
- connection alone is not file copy

### WhatsApp Web + company files
- WhatsApp Web evidence and company-download evidence as separate facts
- direct attachment/referrer/source link required for confirmed WhatsApp transfer
- timing overlap alone is not a confirmed transfer

### Recycle Bin
- distinct deleted file count after metadata/content pairing and deduplication
- original safe name + deletion time + recovery state
- handover comparison only when handover time is independently grounded

### Encrypted files
- distinct protected-file count, not unrelated encryption indicators
- protection type and accessibility state
- company-related subset only when grounded

### Email accounts
- distinct email addresses
- current configured/signed-in vs historical webmail trace
- organization classification from Case intake
- supported last-use/logout/sync time where available

### Credentials in Notepad
- confirm a user-created note contains account plus login/password wording
- safe filename/account/domain/time only
- never reproduce the secret

### Company documents on personal laptop
- distinct company-related documents after deduplication
- relationship basis: body text/OCR/hash/metadata/trusted filename
- personal-device status must come from intake/evidence
- source channel stated only when directly supported

## 4. Retrieval and report-agent safeguards

- Objective-specific RAG queries execute before generic media/document queries.
- AXIOM-style objectives reject indexed chunks that do not contain objective-relevant evidence terms.
- Broad linked artifact totals are marked as candidate evidence and are not supplied as authoritative counts.
- The generic structured-observation draft is discarded for strict objectives so it cannot carry a nearby unrelated total into the final report.
- If exact evidence cannot be grounded, the fallback says that the exact fact could not be determined. It does not substitute an unrelated count.
- Reference-report values are style/coverage examples only and are never copied to the current case.

## 5. Validation

- Python compilation: PASS for modified report/evidence services.
- Focused objective/evidence tests: 16 PASS.
- Observation/report regression tests: 34 PASS.
- TypeScript `reportPagination.ts`: standalone TypeScript compilation PASS.
- Synthetic five-column URL-table simulation: serials `1..15` emitted exactly once with no gaps.
- One unrelated pre-existing catalog-ingest test still fails because `axiom_catalog_ingest._workbook_path` no longer exists; the same failure reproduces on the V3 base and is not caused by this patch.

## 6. Deployment note

Rebuild/redeploy frontend and backend, then recreate/regenerate the report. Existing rendered report pages do not reflow automatically. Saved objective selections are resolved back against the latest report-template rows during generation, so updated objective/procedure text is used when the report is rebuilt.
