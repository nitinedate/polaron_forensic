# EML(X) Evidence Reconciliation V44 - 2026-10-03

## Problem reproduced

The report and the Disk Artifacts UI could disagree for EML(X). The report could show a non-zero EML(X) count while selecting EML(X) in the artifact tree returned zero rows. Email attachment counts could also be non-zero without individual attachment evidence rows.

## Root causes

1. `count_eml_files()` could count MIME-validated/extensionless/carved email occurrences that were not represented by the artifact-list predicate.
2. MIME inventory required `minio_uri`, excluding zero-copy/part-backed evidence that the preview layer could actually read.
3. Extensionless RFC822 messages were detected for counting but were not promoted to canonical RFC822 metadata, so browse/search did not recognize them as EML(X).
4. The email MIME parser stored only occurrence/count information, not examiner-useful headers/body/attachment metadata.
5. MIME attachment occurrences inside an EML/EMLX were counted but had no virtual evidence rows, so clicking Email Attachments could show an empty pane.
6. Carved EML signatures inside an already allocated EML/EMLX could be counted twice.
7. A carved-evidence content accessor was missing, preventing some `carve-*` evidence from opening.

## Fix

- Count EML(X) from the same canonical browseable evidence domain used by the UI.
- Reconcile MIME evidence before count/list operations.
- Promote byte-validated extensionless RFC822 messages into metadata:
  - `resolved_content_type=message/rfc822`
  - `email_mime_validated=true`
  - normalized `.eml/.emlx` display metadata
  - subject/from/to/date/message-id
  - attachment metadata
- Parse extensionless RFC822 through the email parser rather than generic file metadata.
- Read MIME candidates through the forensic content resolver so MinIO, tar-part, and virtual-disk sources work consistently.
- Add virtual evidence rows for MIME attachments with parent artifact ID + MIME `part_index`; UI opens the exact selected attachment bytes.
- Add duplicate protection so carved signatures inside already allocated EML/EMLX sources are not counted again.
- Keep Outlook-derived EML materializations out of the EML(X) category to avoid double counting Outlook Emails.
- Add high-confidence count metadata/warnings for parse failures.

## Expected behavior

For any EML(X) count N shown in the catalog/report, opening EML(X) should return the same browseable evidence domain (subject to pagination). A count must not be created from a hidden detector that cannot produce examiner-visible evidence.

Email Attachments follows the same principle: standalone attachment files, MIME attachment parts and independently browseable carved attachment evidence are visible rows. PST/OST attachment estimates remain diagnostic until materialized and do not inflate the browse count.

## Verification

Focused V44 tests: 12/12 passed.
Relevant email/report/browse suite: 36 passed, 1 pre-existing unrelated test failure (`test_email_count_fallback` uses a dummy DB without `execute`; the same failure exists in the prior project).
Modified backend modules compile successfully with `py_compile`.
