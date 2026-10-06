# Aetheris V9 - Report Evidence Detection / AXIOM-style Alignment

Date: 2026-09-16

## Why V9 was required

V8 correctly made the supplied AXIOM knowledge base authoritative for the *meaning* of an objective, but Section C could still stop at catalog/inventory totals instead of asking the objective against the full record-level evidence already available elsewhere in the report.

That produced contradictions such as:

- the Annexure contains Google Drive/WhatsApp/browser evidence, while Section C says the service could not be identified;
- the User Profile section lists Windows accounts, while the User Accounts objective says the users could not be determined;
- USB rows are available, but the external-HDD objective does not reduce them to distinct physical external disks;
- browser category totals are zero, while a generic observation says relevant malware/phishing/pornography traces were found;
- generic Word/Excel/Outlook totals can appear in an objective that requires a specific account, file, or action.

The reference AXIOM report demonstrates a different reasoning model: identify the exact evidence family required by the question, classify/deduplicate records, correlate supporting records, and then write the observation.

## New V9 reasoning flow

Case Intake objective
-> AXIOM KB objective/procedure
-> required evidence family
-> FULL live job records (same source as Sections A/B/D)
-> objective-specific classification/exclusions
-> semantic deduplication/correlation
-> deterministic case fact
-> evidence validator
-> Report Agent wording
-> simple `This means ...` explanation
-> Analysis Summary rebuilt from the same final Section C observations

The LLM is therefore not the evidence detector. It is the final controlled writer.

## Objective-specific live detectors

### File Access and Handling
Uses specific LNK/Jump List/recent-document targets and timestamps. General document counts are not treated as proof of open/copy/rename/delete activity.

### Malware / Phishing / Pornography URLs
Runs the browser-history category classifier against recovered URLs. A zero category count produces an explicit NOT_FOUND result. A positive result must name objective-specific domains/evidence; generic `relevant traces were found` text is rejected.

### USB and External Device Usage
Uses the live SYSTEM hive + SetupAPI path and classifies USB records. Hubs, cameras, Bluetooth, input/composite devices and storage-interface-only rows are separated from physical external storage.

### Connection of External Hard Disks
Reduces raw USB/SCSI evidence to distinct physical external storage. V9 also parses strongly identified UASP/SCSI external models (e.g. Portable/Expansion/Passport/Elements) while excluding internal NVMe devices. Connection and file transfer remain separate findings.

### User Accounts & Login Activity
Uses the same structured SAM/ProfileList collector as the User Profile section so Section A and Section C cannot disagree about whether accounts exist.

### Cloud Storage
Scans the full recovered browser history for Google Drive, Dropbox, Mega, OneDrive/1drv, SharePoint, iCloud, Box and pCloud. Names the providers found. A web visit is not converted into an upload/download claim without transfer evidence.

### Deleted Files / Recycle Bin
Uses the authoritative deleted-evidence collector. Counts distinct Recycle Bin items and reports recovered deletion times only when present.

### Email Accounts
Extracts actual email/account identities from decoded email/webmail evidence. Outlook message counts or unrelated document counts are not account counts.

### Encrypted Files
Requests the authoritative report-time encryption/header scan and reports the current case count. It never copies the reference report's count.

### Saved Email Login Details / Notepad
Searches user-created text/note evidence for an email identity plus login/password terminology. Secret values are never reproduced.

### Company-related Documents
Uses organization terms from Case Intake and matches them against document filename/path/metadata/indexed content. General Word/Excel/PDF inventory totals are not company-document evidence.

### WhatsApp Web + Company Files
Detects WhatsApp browser endpoints from the full browser history and separately detects company documents. It only claims a WhatsApp file transfer when an attachment/download/referrer/source relationship supports the link. Timing overlap alone is not proof.

## Cross-section consistency

V9 explicitly rebuilds Analysis Summary from the final persisted Section C observations after all objectives are generated. This prevents an older summary from saying `no cloud traces` while Section C or the Annexure shows Google Drive evidence.

Selected objectives also imply supporting Annexure tables. For example, cloud objectives cause a Cloud Service URLs evidence table to be included, USB/external objectives include USB evidence, and WhatsApp objectives include Web Chat URLs.

## Evidence safety

The existing raw-payload controls remain. XML/JSON package content, BlockMap/AppX payloads, internal paths, SQL/query text, parser names and unrelated artifact totals must not appear in the human Observation.

## Important limitation

V9 reproduces the *forensic detection method*, not the historical result values from the reference report. If the current acquisition contains different evidence, the result must be different. If the current evidence genuinely lacks a required artifact, V9 must state the limitation rather than copying the reference finding.

## Validation

Focused V9 report/AXIOM suite: **58 passed**.

Broader report suite: **110 passed, 5 pre-existing failures**. The same five legacy expectation failures are reproducible on the untouched V8 baseline, so V9 introduces no additional broad-suite failures.

Changed Python modules compile successfully.

## Deployment

No PostgreSQL schema migration is required.

Rebuild/recreate at minimum:

- `api`
- `worker-report`

Also rebuild `worker-agent` if that service loads agent/report knowledge in the deployed Compose stack.

Existing reports are snapshots. Use **Recreate/Regenerate Report** after deployment to run the new evidence detection and consistency pass.
