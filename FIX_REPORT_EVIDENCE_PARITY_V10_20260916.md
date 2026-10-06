# Aetheris V10 - Report Evidence Parity / AXIOM-style Detection Fix

Date: 2026-09-16

## Executive finding

The report mismatch has **two independent causes**:

1. **The acquisition identity shown in the two reports is different, but the generated report also had acquisition-metadata bugs.**
   - Reference report: 256 GB SKHynix HFM256GDHTNI-87A0B with a reported SHA1 beginning `51f1534b...`.
   - Current generated report displayed 32 GB and `544fb515...` as SHA1 with drive model/serial blank. Investigation found that the generator was using `bytes_extracted` as if it were physical drive capacity and truncating a registered evidence-file SHA-256 to 40 characters while labelling it SHA1. Therefore those generated values cannot be used to prove that the evidence source is different. V10 fixes both metadata errors.
   - After regeneration, the actual mounted/registered evidence identity must be verified before expecting exact numerical parity with the reference. Exact findings such as 418 encrypted files, 10 Recycle Bin files, or two external HDDs must come from the evidence actually analyzed; they are never copied from the reference report.

2. **There were genuine software defects in evidence resolution.** Even within the currently generated report, Section C could say that evidence was inconclusive while Section B/D already contained relevant records. V10 fixes those defects so Section C, Annexure, Analysis Summary and PDF/DOCX are driven by the same objective-specific fact set.

## What V10 changes


### Forensic imaging metadata correctness

V10 also fixes two report-integrity issues discovered while comparing the acquisition pages:

- `segment_hashes` are SHA-256 hashes of registered evidence files/segments. They are no longer truncated to 40 characters and labelled as an image SHA1. When an explicit acquisition SHA1 exists, the report uses it; otherwise the registered hash is labelled accurately as Evidence File SHA-256.
- `bytes_extracted` is the amount materialized by the extraction pipeline, not the physical source-disk capacity. It is no longer printed as drive capacity. Physical capacity is shown only when it is explicitly available in acquisition/exhibit metadata.

This prevents the report itself from making two acquisitions look different merely because one was partially/filtered extracted or because a SHA-256 was mislabelled.

### One evidence path per report objective

The Report Agent no longer independently guesses from nearby artifact totals. Each objective now requests a deterministic case fact first. The LLM only turns that fact into simple client wording.

Flow:

`Objective -> AXIOM KB -> full case evidence -> objective detector -> classify -> deduplicate -> correlate -> fact -> observation -> simple explanation`

### Cloud storage

The cloud detector now merges:

- live Browser History rows;
- recovered browser-history rows;
- persisted AXIOM query snapshots when a live browser parser did not promote the URL;
- Browser Downloads / Cloud Files / Cloud Activity evidence where available.

It recognizes Google Drive / Google Docs, Dropbox, Mega, OneDrive / 1drv / SharePoint, iCloud, Box and pCloud. The detector names providers it actually finds. Website access is kept separate from proof of upload/download/sync.

The Cloud Annexure now uses the same resolved browser record pool as Section C. This removes contradictions where Annexure contains a Drive URL while Section C reports no cloud provider.

### External hard disks / USB

The detector now distinguishes physical external storage from raw USB/interface rows. It uses USBSTOR plus SCSI/UASP evidence and provenance, and excludes:

- USB hubs;
- cameras;
- Bluetooth;
- keyboards/input devices;
- composite devices;
- generic interface rows when they only represent the same disk;
- internal NVMe disks;
- volume/WPD duplicates.

Physical disks are deduplicated by stable serial/model/device identity. If device records exist but the physical disk cannot be resolved, the result is now **INCONCLUSIVE**, never a false "no external disk" conclusion.

### Recycle Bin / deleted files

A major gap was that Windows `$Recycle.Bin/$I*` descriptor files are commonly extensionless. They could be absent from the promoted artifact set even when the disk manifest still contained them.

V10:

- marks `$Recycle.Bin` as a critical forensic path;
- materializes critical forensic paths before report generation/backfill;
- parses `$I` descriptor bytes at report time;
- pairs `$I` metadata with matching `$R` content by token;
- avoids double counting `$I` and `$R` as separate deleted files;
- exposes original path and deletion timestamp when present;
- adds a Recycle Bin Deleted Items Annexure.

For older jobs, if zero deleted items are seen and historical extraction may not have materialized `$I` files, the result is **INCONCLUSIVE** rather than a confident false zero.

### Email accounts

V10 adds Chromium `Login Data` parsing for account identities. It reads account/user names and URL/timestamps but intentionally does not expose `password_value`.

The email objective merges:

- browser login identities;
- mail/webmail evidence;
- parsed mail/RAG evidence.

Message count is not treated as account count.

### Notepad / saved credentials

The credentials objective now searches indexed/RAG note content and has a raw-note fallback for user-created `.txt`, `.log`, `.md` and `.csv` files under Desktop/Documents/Downloads. It requires account/email evidence together with login/password wording. Secret values are never printed in the report.

### Encrypted files

The deep report-time scan candidate limit was increased from 200 to 2,500 and ZIP/protected-container candidates from 80 to 500, processed in bounded batches. This removes an artificial ceiling that could make a large encrypted-file finding impossible.

V10 still does not copy the reference value of 418. It reports only the encrypted/protected objects supported by the currently analyzed evidence. If the same AXIOM acquisition is required, that acquisition must be ingested.

### WhatsApp + company files

The WhatsApp detector uses the same resilient browser record pool as Cloud detection. It separately answers:

1. Was WhatsApp Web used?
2. Were organization-related files present/downloaded?
3. Is there direct evidence linking a particular file to WhatsApp?

Timing overlap is not converted into a confirmed transfer unless the available evidence supports that linkage.

### Company-related documents

The detector uses the organization/case terms against filename/path, metadata, indexed document text and OCR/RAG text. Total Word/Excel/PDF counts are never treated as the company-file count.

### File access / handling

A broad document count cannot prove open/copy/delete/rename. The objective requires a named file/action supported by LNK/Jump List/recent-file/filesystem/deletion/timeline evidence as appropriate.

### Malware / phishing / pornography

The report uses the actual URL/security-category classifier. Generic Web Related counts cannot produce a positive finding. Zero classified matches remains zero unless another direct security detection exists.

### User accounts and login

User/profile/account evidence is resolved from structured account/login sources rather than the total Windows event-log count.

## Reliability fixes

### Detector failure is no longer treated as a negative finding

V9 could catch an exception from an objective fact detector and then allow a generic zero-result fallback. V10 changes this to **INCONCLUSIVE / examiner review required**. A parser/query error cannot become "nothing was found".

### No fabricated fallback observations

If an Objective card is missing, the generator no longer inserts phrases such as "Nothing matching was found" or "Nothing suspicious was found." It records that an objective-specific result is unavailable and requires examiner review.

### Cache consistency

Browser URL and encryption caches are cleared at the beginning of report regeneration. A previous 30-minute cache cannot cause Section B/C/D to describe different snapshots of the case.

### Client-facing Objective / Procedure

The supplied AXIOM KB remains authoritative internally, but the client report no longer exposes implementation text such as:

- "controlled procedure(s)";
- "mapped primary evidence rules";
- numbered internal collection steps.

The printed Objective and Procedure are short, simple descriptions. Detailed KB procedures remain internal to evidence collection/detection.

## Diagnostic command

Run inside the API container to see the exact deterministic fact that Section C will use for every selected objective:

```bash
python scripts/diagnose_report_objective_facts.py <job-id> [firm_schema]
```

This is the first command to run when the report says "not found" but the examiner expects an artifact. It exposes the detector status, supporting counts, entities/providers/devices/items, limitations and source metadata before LLM wording.

## Expected deployment behavior

- Recreate/Regenerate Report is required after deployment.
- Existing rendered PDF/DOCX files do not change automatically.
- No PostgreSQL schema migration is required.
- For old disk jobs, report regeneration attempts to materialize newly critical forensic paths (including Recycle Bin) from the existing disk manifest.
- If the original disk manifest/artifact source is incomplete, re-index/re-materialize the job.
- If exact parity with the 21-page AXIOM reference is required, ingest/analyze the same 256 GB forensic image represented in that reference. V10 intentionally does not fabricate findings from another image.

## Validation

- V10 focused evidence-parity + V9 live-objective suite: **15 passed**.
- Broader report/AXIOM suite: **91 passed, 6 failed**.
- The same six failures were reproduced on the unmodified V9/V10-base package (**82 passed, 6 failed** there), confirming they are pre-existing legacy-test expectations and not V10 regressions.
- Modified Python modules compile successfully.

