# Release 4: parsing, reports and progressAgent

This update applies to Disk, Android, iOS and the legacy Mobile product. It retains the authenticated WhatsApp recovery and fixed 2,500-character RAG chunks with 800-character overlap from the previous release. GPU embedding remains disabled in the forensic pipeline.

## Parser coverage

| Acquired source | Added or corrected handling |
| --- | --- |
| EML, EMLX, MSG, MBOX, MBX | Complete email bodies, mailbox messages, headers, MIME attachments and nested messages; explicit damaged/unsupported parsing errors |
| JSON, JSONL, NDJSON, XML, CSV, TSV, plist/bplist | Structured records, full readable text, export messages and source-record pointers; UTF-8/UTF-16 support |
| Readable SQLite message stores | Stream recognizable message tables beyond the former row cap; domain parsers take priority; WAL/journal replay remains available |
| BIN, DAT, BLOB and unknown binary data | Exact byte offsets for readable fragments; validated protobuf wire fields where applicable; fragments remain unverified bytes |
| Acquired Android package/account/user records | Current packages distinguished from retained package references; account identity fields only; no password/token text in report prose |
| WhatsApp crypt12/14/15 | Authenticate and decrypt with acquired matching keys, then parse plaintext databases and available residual records; invalid key-file command output is rejected |

Existing browser, document, media, application and recovery parsers remain in the registry. This is broad acquired-format coverage, not a promise to decode every proprietary or encrypted format. A binary string is not promoted to a chat. Encryption formats without a supported decoder and a legitimate key remain explicitly unreadable. Missing or overwritten evidence cannot be created by a parser.

Communication exports have an explicit 256 MiB input ceiling; SQLite retains the 768 MiB ceiling. Oversize sources create a processing exception. The bounded read cache stores at most 64 MiB and distinguishes complete bytes from prefixes, including SQLite companion context.

## Suspicious Activity and matching reports

Disk and Mobile use the same A4 page geometry, section positions, letterhead, watermark and pagination rules. Mobile retains truthful device/extraction headings in the corresponding Disk positions. The new **Suspicious Activity** section follows Objective, Procedure & Observation and precedes Annexure.

Source rules identify contextual requests to disclose credentials/OTPs, payment pressure, deletion of chats/evidence, remote-access requests, selected application references and executable/disguised downloads. Media observations retain source-image derivatives or sampled video frames. Each candidate includes an explanation, source path, available SHA256, artifact/record ID, method and time. Images included in the report are read from the job's retained evidence object and verified against their frame hash. A missing or mismatched picture is an export error, not a substituted image.

Each candidate occupies its own report page. The separate **Examiner observations** page is editable using the existing report Edit control; saved notes appear in UI, PDF, Word and HTML exports. Source captions are kept separate. Candidates require examiner verification and do not establish wrongdoing. Video coverage is sampled, and its actual frame timestamps and sampling limits remain available.

## One coordinator

Only **progressAgent** runs outside the required process stages. The independent observe/repair/performance council no longer dispatches work. The unused performance-agent module and healing panel are removed; compatibility entry points delegate to progressAgent. Historical recovery-ledger reads perform no recovery or schema writes.

The dedicated CPU-only progress worker checks every 15 seconds. After 60 seconds without useful progress, it distinguishes user pause, bounded long operations, queued work, unavailable consumers and dependency waits from an invalid stall. A heartbeat alone is not counted as useful progress. Completed/failed/skipped counters, persisted records, reviewed frames and saved report sections advance progress.

Stage and report execution use an owned subprocess. When a live process stalls beyond its recorded operation deadline, the coordinator asks the owning worker to stop that subprocess and resume from persisted checkpoints. It never broadcasts Celery termination. On Linux, the stage process also exits if its owning worker dies abruptly, preventing abandoned stages from continuing. Recovered claims use the existing advisory lock; report recovery rechecks pause and ownership under the lock. Only the dead owner's exact lease tokens may be released. Invalid recovery retries have a three-dispatch budget; dependency checks do not consume it. Persistent source failures remain visible for correction.

Recorded operations have deadlines, so legitimate database/CPU/model calls can exceed one minute without being killed. Missing consumers or unavailable external services are surfaced as dependency waits; the coordinator does not provision Docker services, unlock phones or invent missing keys. The progress console shows its decisions and reasons.

## Implemented performance changes

| Change in code | Purpose |
| --- | --- |
| Dedicated monitor queue, one worker, prefetch 1 | Keep checks responsive while extraction/report workers are occupied |
| Monitor connection pool 2 + overflow 1; 15-second SQL and 5-second lock bounds | Bound monitoring database contention |
| Active-report index and one aggregate query for priority-category counts | Reduce repeated scans and database round trips |
| Keyset batches and streamed message rows | Retain complete records without loading every row into one result list |
| 64 MiB per-worker read cache, cleared at bundle boundaries | Reduce repeat reads while bounding retained bytes |
| Stage subprocesses and saved checkpoints | Release stage memory on exit and resume completed work |
| Lazy report routes and evidence-picture loading | Delay report/editor and picture work until needed |
| One progress poll after each completed response | Avoid overlapping UI polling requests |
| Timezone suffix removed from log-console display | Simplify display while keeping stored times and filter conversion |

For the host, keep PostgreSQL, Redis, temporary derived files and application containers on SSD where available; process acquired evidence from the selected source location. Benchmark one representative HDD case and one mobile dump before changing worker limits. Record stage duration, files/second, queue delay, peak RSS, database waits and GPU busy time. Keep the existing four-CPU-worker cap and exclusive OCR/vision GPU permit until measurements justify a change. No extraction-time or GPU-accuracy claim has been established on the user's hardware.

The large shared frontend bundle still produces Vite's size warning. Report routes are split in this update; a broader dependency split should be based on measured loading cost, since it affects every product.

## Apply and verify

1. Pause active jobs and retain a rollback copy of deployment code. Preserve host credentials, drive overlays and acquired-evidence directories when extracting the updated source archive.
2. From the project root in PowerShell, run `./scripts/Apply-Disk-Mobile-Serial.ps1 -PrepareVisionModel`. The script builds without cache, creates the new progress worker, migrates tenant schemas and adopts finalized active jobs. Use its documented `-Products`, project-name and overlay options for your deployment.
3. For historical cases, use **Reprocess mobile evidence**, or run the script with `-ReprocessReady` to reprocess finalized ready cases across the selected products. No device acquisition bytes are replaced.
4. Generate a new report after reprocessing; existing saved reports are retained. Check messages/email attachments, category counts, source previews, Suspicious Activity pictures and saved examiner notes in both PDF and Word.
5. Validate live-device extraction with known source data and matching WhatsApp keys. Confirm one-minute decisions, legitimate model waits, pause/resume and recovery in the progress console. Compare sampled-video captions with original frames before approving observations.

Read `DISK-MOBILE-SERIAL-RELEASE.md` for complete deployment commands and `WHATSAPP-RECOVERY.md` for acquisition/key requirements. Docker/handset/CUDA acceptance is still required on the central host.
