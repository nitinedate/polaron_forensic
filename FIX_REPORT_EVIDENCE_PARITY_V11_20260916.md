# Aetheris V11 — Report evidence parity fixes

Date: 2026-09-16

## Why the generated observations differed

The differences were not primarily an LLM wording issue. They came from gaps between the evidence already present in the case/disk index and the record-level evidence actually supplied to Section C.

### Recycle Bin

V10 treated `$Recycle.Bin` as critical only when the normalized path contained `/$recycle.bin/`. A normal volume-root path such as `$Recycle.Bin/S-1-5-21/.../$Ixxxx` does not have that leading slash, so old jobs could backfill only part of the Recycle Bin. Section C could then report a partial count such as 1.

V11:
- accepts root-level `$Recycle.Bin/...` and `Recycle.Bin/...` paths as critical forensic paths;
- materializes them during report recreation;
- compares the disk-manifest `$I` descriptor count with the materialized descriptor count;
- refuses to publish a partial count as a final count;
- counts only successfully parsed `$I` descriptors, pairing `$I/$R` by the shared token;
- returns `INCONCLUSIVE` if manifest/materialized/parsed coverage is incomplete.

### Encrypted files

V10 read only the first 4 MB of each ZIP during the deep report scan. For archives with hundreds of encrypted members, local ZIP headers after the first 4 MB were not seen. This can produce a partial count such as the observed `MFGSTAT.zip (314 encrypted entries)`.

V11 reads the complete ZIP whenever the archive is within the bounded 128 MB report-scan limit, expands the ZIP candidate set, and increases the non-ZIP encrypted candidate ceiling. The reference count is never copied; if the current archive truly contains 418 encrypted members, the scanner must independently recover 418.

### Email login details in Notepad

V10 relied on RAG plus a narrow live fallback. It could miss:
- Windows paths stored with backslashes;
- UTF-16/UTF-16LE Notepad files;
- user-root/OneDrive notes outside only Desktop/Documents/Downloads;
- parsed text that had not been promoted to RAG.

V11 searches parsed text, RAG/indexed text, and live user-note files. It supports UTF-8, UTF-16, UTF-16LE/BE and Windows-1252. It never prints the recovered password/secret.

### Company-related documents

V10 mainly used filename/path matches and RAG text. A document already present in `job_artifacts` but not indexed into RAG could therefore be missed.

V11:
- expands company identity terms from `organization`, `requesting_agency` and Vol-18/client fields;
- searches filename/path and all relevant indexed text;
- falls back to live PDF/DOCX/XLSX/PPTX/TXT/CSV/RTF content inspection;
- reports a negative result only when the covered evidence supports it;
- returns `INCONCLUSIVE` if the bounded live scan did not cover the available candidate corpus.

### Contradictory Observation text

V10 could pass both a record-level `case_fact` and a generic KB report result to the wording model. This allowed contradictions such as:

`1 distinct Recycle Bin item was identified. No deleted files were found.`

V11 hides generic report results from the LLM whenever a specialized record-level case fact exists. Validation also explicitly rejects `no ... were found` wording when the case fact is `CONFIRMED`.

## Evidence-source warning

The reference report and the previously generated report do not show the same acquisition identity. The reference report records a 256 GB SKHynix drive and a SHA-1 beginning `51f1534b...`, whereas the earlier generated report represented a 32 GB extracted amount and a different registered hash. V10 already stopped mislabelling `bytes_extracted` as physical disk capacity and stopped truncating SHA-256 to look like SHA-1.

Before demanding exact parity (10 Recycle Bin items, 418 encrypted files, the same Notepad note, etc.), confirm that the current job is analysing the same acquisition/evidence source. V11 improves detection; it does not copy reference-report values into a different evidence set.

## Validation

Focused V10+V11 evidence parity suite: 17 passed.

Broader report/AXIOM subset: 97 passed, 3 failed. The same 3 tests also fail unchanged on the V10 baseline, so they are pre-existing and unrelated to V11.

## Deployment

Rebuild/recreate at least:
- `api`
- `worker-report`

Rebuild `worker-agent` as well if it imports report services in the deployment.

Then use **Recreate/Regenerate Report** so the critical-path backfill, full ZIP scan and new record-level detectors run against the current job.

Diagnostic command:

```powershell
docker compose exec api python scripts/diagnose_report_objective_facts.py <JOB_ID> firm_aetheris
```

For the RRP job used in previous examples:

```powershell
docker compose exec api python scripts/diagnose_report_objective_facts.py b8c65154-76a7-424b-a23b-231f268870c5 firm_aetheris
```
