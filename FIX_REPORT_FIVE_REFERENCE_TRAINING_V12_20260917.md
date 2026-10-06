# V12 - Five Forensic Report Reference Training

## Purpose

V12 integrates the five supplied Ex-1 through Ex-5 forensic reports as a curated **reference exemplar corpus** for the Aetheris Report Agent. This is not model-weight fine-tuning. The corpus controls evidence questions, Objective/Procedure wording, evidence-to-finding boundaries, Annexure traceability, and cross-section consistency while current-case collectors remain the only source of facts, counts, dates, URLs, accounts and devices.

## What was learned from the five reports

The reports repeatedly use a stable flow:

1. **Section B - Artifacts**: broad artifact inventory and counts.
2. **Section C - Objective / Procedure / Observation**: the Objective asks a narrow forensic question; the Procedure names evidence families; the Observation reports only the supported current-case result.
3. **Section D - Annexure**: concrete URLs, devices, RDP rows, etc. support the Section C finding.
4. **Section E - Analysis Summary**: a compressed restatement of the final Section C conclusion.

The recurring objective patterns are:

- Verify Use of Unauthorized Remote Access Tools
- USB and External Device Usage
- Cloud Storage Service Usage
- Analysis of Chat / Communication Apps
- Analysis of Social Media Activity
- Internet and Network Connection Review
- Anti-Forensics Tools
- Torrent URLs
- Malware / Phishing URL Verification

## Evidence decision rules added

### Remote access

Installed remote-access software, execution evidence, and RDP/session evidence are separate facts. Installation does not prove use. RDP does not prove unauthorized control. A stronger unauthorized-access conclusion requires separate case evidence.

### USB / external devices

Raw USB rows are classified and deduplicated. Hubs, input devices, cameras, Bluetooth, internal drives, interface rows, and volume duplicates do not become separate external-storage findings. Connection does not prove file copying.

### Cloud storage

The detector names distinct supported providers from current browser/cloud evidence. Service access does not prove upload/download/share/sync. The provider taxonomy now covers Google Drive, Dropbox, Mega, OneDrive/SkyDrive, Box, Egnyte, Sync.com, Tresorit, iDGard, pCloud, iCloud and common transfer/storage providers.

A deliberate correction is included: `id5-sync.com` is not treated as Sync.com cloud storage. It is ad-tech identity-sync infrastructure even though one reference Annexure placed it under Sync.com.

### Chat / communication

The agent identifies supported services such as WhatsApp Web, Telegram Web, Discord, Slack, Zoom, Google Hangouts/Chat and GoToMeeting. Service access is not automatically treated as a message, call, attachment or file transfer.

### Social media

The agent identifies supported services but does not infer posting, messaging, account ownership or authorship from a URL alone.

### Internet / network

The agent can combine meaningful browser-service access and RDP/session traces, but does not turn access into messaging or data transfer without direct evidence.

### Anti-forensics

Cleanup/wiping software presence is separated from execution and from proof of evidence destruction. Tools such as CCleaner can be reported as present without claiming they were used to erase evidence.

### Torrent

Torrent/magnet URLs and torrent-client evidence are classified separately from actual file transfer. A deliberate correction is included: ordinary Archive.org pages are not classified as torrent activity merely because a reference report listed them under a Torrent heading.

### Malware / phishing

Classified URL access is kept separate from download, execution, compromise or infection.

## Section B artifact model

The corpus records the recurring artifact categories used by the five reports:

- Connected Devices
- Application Usages
- Communication
- Documents
- Email & Calendar
- Encryption & Credentials
- Media
- Operating System
- Web Related

These categories guide artifact selection and report structure. Their example counts are **not** stored as current-case facts.

## Platform awareness

The Ubuntu/Linux exemplar does not contain the same Windows-only artifact groups as the Windows reports. The corpus therefore tells the Report Agent that missing platform-specific evidence must not automatically become a negative finding. Coverage is evaluated before a `NOT_FOUND` conclusion.

## Consistency rules

V12 adds the following exemplar-derived constraints:

- A positive Section C finding must be traceable to current-case records.
- Section C cannot say no cloud/device/chat/social/RDP evidence when the authoritative records/Annexure establish the opposite.
- Section E must reuse the finalized Section C result.
- Section B totals cannot be substituted for objective-specific counts.
- Incomplete evidence coverage produces `INCONCLUSIVE`, not a fabricated zero.

## Files added/changed

Added:

- `backend/app/knowledge/report_reference_corpus/five_forensic_reports_v1.json`
- `backend/app/services/report_reference_kb.py`
- `backend/scripts/diagnose_reference_report_training.py`
- `backend/tests/test_five_report_reference_training_v12.py`

Updated:

- `backend/app/services/axiom_forensic_kb.py`
- `backend/app/services/report_examination_narratives.py`
- `backend/app/services/report_objective_case_facts.py`
- `backend/app/services/report_objectives_observation_service.py`
- `backend/app/services/report_evidence.py`

## Validation

Focused V12 + V9/V10/V11 report/evidence/KB tests: **48 passed**.

Broader `test_report*.py` + AXIOM integration suite: **131 passed, 6 failed**. The identical six failures were reproduced against the untouched V11 package, so V12 did not introduce them.

Run the corpus diagnostic inside the API container:

```bash
python scripts/diagnose_reference_report_training.py
```

The output lists the five-report corpus fingerprint, corpus counts, objective patterns, KB report mappings and Annexure mappings.
