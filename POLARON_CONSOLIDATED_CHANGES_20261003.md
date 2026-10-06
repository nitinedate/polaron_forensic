# Polaron - Consolidated Changes Applied to `pol.zip`

**Date:** 2026-10-03  
**Base:** User-supplied `pol.zip`  
**Merge strategy:** Preserve changes already present in the supplied project and merge the missing forensic-accuracy, extract-then-process, and EML(X) evidence-reconciliation work from the prior review.

## Point-wise description

### A. Disk forensic extraction and processing

1. **Single evidence extraction pass** - the disk/E01/raw source is walked and extracted once. Downstream processing no longer needs to reopen/re-extract the source just to continue normal analysis.
2. **Strict Extract -> Process barrier** - `EXTRACT_THEN_PROCESS=true` is the default. Artifact registration, parsing, OCR, RAG, entity enrichment and inventory wait until evidence extraction is complete.
3. **Streaming Phase-3 disabled by default** - `PHASE3_STREAM_DURING_EXTRACT=false`, `PHASE3_STREAM_RAG_DURING_EXTRACT=false`, and `PHASE3_STREAM_OCR_DURING_EXTRACT=false` prevent CPU/GPU/IO competition with the source-critical extraction stage.
4. **Existing newer extraction locking retained** - the supplied project already moved the CPU-heavy extract admission slot ahead of virtual-disk work and protects duplicate resumes; that behavior is preserved while adding the strict post-extraction barrier.
5. **No duplicate parse/inventory queue in strict mode** - after extraction completes, one post-extraction orchestrator starts the remaining pipeline. Separate parse/inventory tasks are queued only for legacy streaming mode.
6. **Clear extraction transition logging** - the central log records `Extraction barrier complete` before the downstream pipeline is queued.
7. **Evidence-manifest gating** - post-extraction work is allowed only after the extracted evidence state/manifests are ready, avoiding misleading partial downstream results.
8. **Honest job progress** - downstream cards are parked in `Waiting for evidence extraction to finish` while extraction is incomplete rather than showing old/partial work as active.
9. **Post-extraction stage naming improved** - `Materialize` is presented as `Register artifacts`, clarifying that this step registers extracted evidence rather than re-copying the forensic image.
10. **Phase-local percentages** - extraction progress no longer makes the whole job appear to be 99% complete while OCR/RAG/inventory are still outstanding.
11. **Filesystem enumeration separated from extraction denominator** - while the filesystem tree is still growing, the UI can show files discovered so far instead of pretending the final denominator is known.
12. **Existing HDD/SSD/NVMe performance work retained** - source-media-aware extraction, streaming large files, compressed inventory ledgers, checkpointing, one-pass tar/zstd reading and existing high-throughput settings remain in place.

### B. Resource governor / Redis availability

13. **`redis-capacity` DNS/transport outage no longer blocks extraction indefinitely** - `RESOURCE_GOVERNOR_FAIL_OPEN_ON_UNAVAILABLE=true` allows local guarded extraction to continue when the shared capacity service is unreachable.
14. **Real capacity exhaustion still remains protected** - fail-open applies to the unavailable coordination service, not to a valid `busy`/capacity denial response.
15. **Local CPU/IO admission remains enforced** - the project continues using the local product/CPU-heavy lock even when the shared capacity Redis cannot be reached.

### C. PostgreSQL queries, migrations and indexes

16. **Migration 037 is part of the platform migration path** - the search-performance migration is included by both Linux and PowerShell migration scripts.
17. **Rich search-index function is preserved** - startup fallback logic no longer overwrites the migration-owned `apply_firm_search_indexes_v1()` implementation with a minimal version.
18. **Artifact-search indexes retained** - job/path, filename, extension, MIME/resolved-MIME, trigram and parse-result indexes remain available for large artifact sets.
19. **Vulnerability composite indexes retained** - case/job/status/severity/host/port/target paths have composite indexes for scanner progress and report queries.
20. **Query methodology is deterministic** - report agents are guided to scope by tenant/schema + job/case first, use bound parameters, stable deduplication keys, indexed predicates and explicit evidence-state separation.

### D. Forensic report agent accuracy

21. **Reference corpus expanded to all 13 supplied forensic reports** - the knowledge corpus covers workstation/disk, email, Google Takeout/cloud, shared-drive/permissions, account activity and combined-report patterns.
22. **Reports are methodology exemplars, not case facts** - names, counts, URLs, devices and conclusions from sample reports are never treated as facts in a new investigation.
23. **Common report grammar established** - inventory -> objective -> procedure -> record-level evidence -> exclusions/deduplication -> observation -> limitation -> annexure traceability -> summary.
24. **Negative findings require coverage** - an agent should not claim `not found` unless the relevant collector/source coverage is known to be complete enough for that statement.
25. **USB/device reporting is deduplicated by physical identity** - interfaces/volumes belonging to one device should not automatically inflate the number of external physical devices.
26. **Email-account reporting carries account state** - current configured accounts are separated from historical correspondence/browser/session traces.

### E. EML / EMLX parsing, counting and evidence browse

27. **One canonical EML(X) evidence domain** - counting, parsing and browsing use the same RFC822/EML evidence rules instead of separate incompatible predicates.
28. **Extensionless RFC822 messages are supported** - byte-valid email messages can be promoted to `message/rfc822` metadata without renaming or altering source evidence.
29. **Zero-copy/part-backed messages are scanned** - MIME inventory is no longer limited to records having only a MinIO URI; it can use the same forensic-content resolver used by the evidence browser.
30. **Full MIME metadata is parsed** - From, To, CC, BCC, Subject, Date, Message-ID, text/HTML information, attachment count, MIME types and attachment filenames are retained where present.
31. **EML(X) counts are browseable** - a non-zero EML(X) category is reconciled to evidence rows the examiner can open instead of showing `count > 0` with `0 matching` in the middle pane.
32. **Historical jobs self-heal on EML browse/count** - an EML inventory scan can promote already-extracted valid RFC822 evidence into the canonical metadata model; the original E01 does not need to be extracted again.
33. **MIME attachments are individual evidence rows** - attachments embedded in an EML/EMLX can appear under `Email Attachments` with their filename/content type.
34. **Exact attachment opening** - the UI opens the selected MIME part using the parent artifact id + MIME part index rather than reopening only the parent email.
35. **Carved/allocated EML double counting is reduced** - carved signatures inside an already allocated EML/EMLX are not blindly added as separate confirmed EML files.
36. **Outlook-derived messages remain category-separated** - derived Outlook evidence can be MIME-parsed while the EML(X) report category avoids double counting the same Outlook representation.

### F. Mobile forensic processing

37. **UFD/UFDX/ZIP companion resolution retained** - descriptors can resolve companion FileDump ZIP/UFD/PAS references portably, including descriptors that contain Windows absolute paths from another workstation.
38. **Path safety retained** - descriptor paths are treated as metadata and companion resolution is constrained to the evidence area rather than trusting arbitrary host paths.
39. **WhatsApp crypt12/14/15 processing retained** - encrypted Android `msgstore` backups can use a usable same-evidence WhatsApp key with the existing fail-closed decryptor; no brute force or key guessing is introduced.
40. **Decrypted WhatsApp DB validation retained** - decrypted output must validate as the expected SQLite/message-store structure before being treated as usable evidence.
41. **Deleted/recovered state separation retained** - allocated live, logical-deleted, filesystem/trash recovered, WAL/journal/freelist residual, carved/unallocated and unverified candidates remain distinct.
42. **No fabricated deleted evidence** - AI/RAG cannot convert a residual string/carve into a confirmed deleted chat unless deterministic validation supports that promotion.
43. **Android and iOS platform isolation retained** - changes in the Android acquisition/parse path do not automatically alter the iOS path and vice versa.
44. **Encrypted iOS limitation remains explicit** - a password by itself is not treated as proof that an encrypted iPhone backup is already materialized/decrypted; a genuine decrypt/unback stage is required before normal parsing.

### G. Artifact console and evidence presentation

45. **Complete artifact catalog behavior retained** - categories and zero-count definitions stay visible so examiners know what was checked.
46. **Actual files remain the evidence source** - artifact rows carry source path/provenance and open/download behavior rather than reporting only aggregate counts.
47. **Email/cloud/social/web artifact families retained** - EML/EMLX, attachments, cloud-service URLs, web-chat URLs, social URLs and related evidence remain represented in the artifact console.
48. **Windows forensic artifacts retained** - LNK, Jump Lists, logs, Recycle Bin, installed applications, USB/device evidence and related Windows artifacts remain in the catalog/report model.
49. **Examiner-review signals remain non-conclusive** - review flags identify evidence for attention; they are not automatically presented as wrongdoing/malware conclusions.

### H. Vulnerability scanner fidelity

50. **Accuracy-first TCP profile retained** - central defaults keep the full TCP-oriented scanning profile rather than silently reducing coverage for speed.
51. **`GVM_OPTIMIZE_TEST=false` retained** - the central server stays aligned with the accuracy-focused Greenbone/Nessus-fidelity configuration established in the previous review.
52. **Nessus-style severity/risk compatibility retained** - the previous weighted risk/severity mapping and scanner-report fidelity changes remain present in the supplied project.
53. **Per-IP progress architecture retained** - target/job/status indexes and the existing progress model remain available for Waiting/In progress/Completed/Fail presentation.

### I. Git and repository hygiene

54. **Root `.gitignore` added.**
55. **`/evidence/` is explicitly ignored** so forensic evidence/case payloads are not accidentally committed to Git.
56. Python caches, pytest/mypy/ruff caches, virtual environments, Node build outputs, local `.env`, logs, temporary files and local DB backup files are also ignored.
57. `.env.example` is explicitly allowed and now documents the strict extract-then-process defaults.

## Deployment defaults added/aligned

```env
EXTRACT_THEN_PROCESS=true
PHASE3_STREAM_DURING_EXTRACT=false
PHASE3_STREAM_RAG_DURING_EXTRACT=false
PHASE3_STREAM_OCR_DURING_EXTRACT=false
RESOURCE_GOVERNOR_FAIL_OPEN_ON_UNAVAILABLE=true
GVM_OPTIMIZE_TEST=false
```

## Evidence-integrity note

The changes improve discovery, reconciliation and recoverability handling, but they do not guarantee that overwritten, vacuumed, securely deleted, encrypted-without-key, or never-acquired evidence can be recovered. Such cases must remain visible as limitations rather than synthetic evidence.
