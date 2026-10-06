# Aetheris report pagination + AXIOM-style Observation fix

Date: 2026-09-16

## What this patch fixes

1. Objective / Procedure / Observation pages now use the available A4 body before opening another page.
2. When substantial room remains, the next O/P/O panel starts in that free space and continues on the following page if necessary; labels are never left orphaned at the bottom. Small gaps still move the panel intact so the report does not become over-fragmented.
3. PDF export uses the actual printable A4 body height (297mm - 44mm top - 26mm bottom = 227mm).
4. The report agent now uses evidence contracts for the eight AXIOM-style reference objectives. It must retrieve exact case facts even when the first deterministic draft is already short.
5. Reference-report values are style examples only. The agent is explicitly forbidden from copying sample counts, dates, email addresses, names, services, or conclusions into a new case.
6. USB evidence now creates a separate de-duplicated external-storage view so raw USB/hub/interface rows are not treated as physical external hard disks.

## Observation rule

Observation must be 2-5 simple sentences for a non-technical reader:

- Sentence 1-2: exact supported finding (distinct names/counts/time/state when present).
- Sentence 2-4: case meaning, using cautious language.
- Final sentence when needed: limitation (for example, connection is not proof of copy; website access is not proof of upload).

Do not place internal paths, registry names, parser names, query keys, status codes, passwords or tokens in the client Observation.

## Objective-specific evidence questions

### Access to Cloud Storage Services

- Which distinct cloud services were accessed? De-duplicate repeated URLs/sessions by service.
- Which browser/user profile and earliest/latest supported access time apply?
- Is there direct upload, download or sync evidence, or only website access?
- Which organization-related documents are content/OCR/hash confirmed rather than filename-only?

Expected observation: name supported services; separate access from transfer; never claim upload from a URL visit alone.

### Connection of External Hard Disks

- How many distinct physical external HDD/SSD devices exist after de-duplicating USBSTOR, SetupAPI, volume and mount rows?
- What model/serial/stable identity and connection time are supported?
- Exclude hubs, cameras, Bluetooth adapters, input devices and internal disks.
- Is there file-open/write evidence from the same external volume during the connection window?

Expected observation: report physical-device count and identities when available; connection alone does not prove copying.

### Use of WhatsApp Web and Download of Company Files

- Was WhatsApp Web confirmed, and in which browser/profile/time window?
- Which downloaded files are company-related by filename plus content/OCR/hash/metadata?
- Is there a direct chat attachment/referrer/source record linking the download to WhatsApp?
- If there is only temporal overlap, state that as possible correlation, not confirmed transfer.

### Deleted Files Found in Recycle Bin

- How many distinct deleted files exist after pairing/de-duplicating Recycle Bin metadata/payload records?
- What original names, deletion times, size, user and recovery state are supported?
- Which deleted files are company/case related by content/OCR/metadata?
- If intake contains handover/submission time, did deletion happen before or after it?

### Presence of Encrypted Files

- How many distinct encrypted/password-protected files exist?
- What type of protection/container is present and were contents accessible?
- Which files are confirmed company/case related?
- Do not describe encryption as concealment or wrongdoing without separate evidence.

### Email Accounts Used on the Laptop

- Which distinct email addresses were recovered?
- Is each account currently configured/signed in, a historical webmail session, or another trace?
- Which addresses match the organization/domain from Case intake?
- What last-supported login/logout/sync/use time is available?

### Storage of Email Login Details in Notepad

- Is there a user-created note containing an email/account plus password/login wording or another credential indicator?
- Which safe display filename, owner and timestamp apply?
- Does the account/domain match the organization?
- Never reveal the password/token/secret itself in the report.

### Storage of Company-Related Documents on Personal Laptop

- How many distinct related documents exist after de-duplicating copies where possible?
- Is the organization match filename-only, metadata, body text, OCR, email-attachment metadata or known hash?
- What safe display names/document types/timestamps are supported?
- Is the device actually established as personal in Case intake/evidence?
- If a source channel is known (email, browser download, cloud sync, etc.), state it; otherwise do not infer it.

## Files changed

- `frontend/src/lib/reportPagination.ts`
- `backend/app/services/report_markdown_html.py`
- `backend/app/services/report_objective_evidence.py`
- `backend/app/services/evidence_contract.py`
- `backend/app/services/report_objectives_observation_service.py`
- `backend/app/services/report_observation_style.py`
- `backend/app/services/forensic_inventory.py`
- Regression tests under `backend/tests/`

## Validation performed

- Python compile checks passed for modified backend modules.
- Focused backend regression suite: 55 passed.
- External-storage de-duplication test: passed.
- TypeScript compile check for `reportPagination.ts`: passed.
- Direct Node simulation confirmed that a following O/P/O panel uses substantial leftover space and continues without an orphan Objective/Procedure/Observation label.
- One pre-existing unrelated test in the previous package (`test_all_catalog_objectives_have_numbered_procedures`) still fails because the catalog has 37 objectives while the static procedure map has 27. The same failure occurs in the prior package and was not introduced by this patch.
