# Disk / Mobile priority evidence and scanner integration — release 16

Release 16 starts the validated public HTTPS gateway on 443 before optional product builds/startup, releases owned stale certificate bootstrap containers and verifies public bindings. Read **PUBLIC-HTTPS-443-FIX.md**.

Release 15 stacks running stages above a full-width job log, with three stage cards per desktop row and readable wrapped log messages. Read **JOB-LOG-LAYOUT.md**.

Release 14 keeps pending stage agents silent: waiting recommendations cannot dispatch tasks or recovery issues, and informational dependency-wait chatter is excluded from new and existing pipeline logs. Warning/error/progress evidence remains visible. Read **QUIET-AGENT-WAITS.md**.

Release 13 bypasses the Windows user pip wheel cache during examiner-kit installation and checks each native installer exit code. Read **EXAMINER-KIT-CACHE-FIX.md**. Docker dependency caching is unchanged.

Release 12 adds SMTP TLS/authentication compatibility, a single retry before submission, visible access-token delivery errors and a safe SMTP diagnostic command. Read **SMTP-DELIVERY-FIX.md**. External provider authentication/inbox delivery needs target-host validation.

Release 11 fixes Windows PowerShell stderr handling for optional legacy-volume migration and first-use persistent-volume creation. Missing legacy MinIO/model caches are skipped; real daemon/permission errors fail. Volume copies are staged and failed copies remain unready and retryable. Read **DOCKER-VOLUME-PROBE-FIX.md**.

Release 10 fixes fresh Windows Docker startup for local, Nitin and production: initialize a missing root `.env` and host settings before Compose, retain existing configuration, verify required build/configuration files, and create resolved runtime storage directories. Application rebuilds and dependency caching remain active. Read **DOCKER-STARTUP-FILES-FIX.md** and **script_docker/README.md** for commands and verification.

Release 9 adds automatic keyed WhatsApp recovery before native artifact parsing: original .crypt plus CRYPT5/7/8/9/10/11/12/14/15, authenticated modern SQLite/JSON/ZIP/image/binary payloads, safe archive-member registration and verified derived-file reads. Legacy unauthenticated results retain integrity warnings. Missing/mismatched keys and unsupported formats remain explicit coverage gaps. The latest supplied CRYPT-family features and test commands are preserved in this combined release. Original ciphertext is retained and identical database snapshots share one derived database. Read **WHATSAPP-CRYPT-RELEASE.md** for format-specific key requirements, the 12-check runnable synthetic case and verification. Updated Mobile and dedicated WhatsApp decryption/test flow PDFs are in **docs/process-flows**. A CRYPT14 file cannot supply its own key. Release-8 Windows deployment files and canonical scanner sources are preserved.

This release completes the serial processing code update and adds priority web, WhatsApp, Android media/document evidence and source-linked image/video observations. GPU embedding is removed from the Disk and Mobile pipeline. Forensic RAG uses text search with 2,500-character chunks and 800-character overlap. The Disk/Mobile source and service boundaries remain preserved; release 6 updated the Laptop/central Vulnerability scanner integration; release 7 adds private WhatsApp key capture into Intake and retires legacy huddle deliveries. See `WHATSAPP-KEY-INTAKE-RELEASE.md` for the new controls and verification. A dedicated CPU-only `worker-progress` is added to each Disk/Mobile deployment.

Release 8 updates the three Windows `script_docker` launchers. Application code compiles on every launch while dependency layers stay cached. Production uses trusted IP-only HTTPS; Nitin uses trusted domain/IP HTTPS. A persistent Certbot service renews certificates and reloads nginx. Read `script_docker/README.md` for configuration, ports 80/443, Windows deployment and current validation. The smaller startup patch applies to release 7; the complete project retains all prior forensic and scanner changes.

Release 6 implements the attached 52-service scanner guide, policy/evidence audit and coverage appendix; it adds the updated implementation PDF and complete service CSV. It also adds the separate Disk, Mobile and Vulnerability Scanner flowchart PDFs and the scanner ODT in **docs/process-flows**. It fixes canonical Laptop Scanner packaging, per-IP API/UI progress, own-scanner readiness, coverage flags and numeric scoring provenance. Read **SCANNER-INTEGRATION-V153-RELEASE.md** for deployment and verification. Live Windows/Docker/Greenbone and phone/GPU acceptance remain pending.

Release 5 adds the runnable **`Test-Live-Phone-GPU.ps1`** command, authenticated backup/message verification, real CUDA/OCR/vision acceptance, redacted diagnostics and a host-safe private-reader/key-validator import fix. Read **`LIVE-PHONE-GPU-VERIFICATION.md`** and run the command on the central host with its authorized phone attached; this editing environment has no live phone/GPU connection.

Release 4 adds email/mailbox and structured/binary parsers, a dedicated **Suspicious Activity** report section with verified source pictures and editable examiner observations, matching Disk/Mobile page structure, and the single **progressAgent** coordinator. Read **`PROGRESS-REPORT-PERFORMANCE.md`** for format coverage, one-minute checks, performance changes and deployment acceptance.

The previous WhatsApp update remains included: authenticated crypt12/14/15 parsing with all collected keys, corrected Android private acquisition, TXT chat exports, decrypted free-leaf-page recovery, complete chat browsing and an effective **Reprocess mobile evidence** action. Read **`WHATSAPP-RECOVERY.md`** for the exact key requirements, local recovery utility, existing-case steps and follow-up verification. A parser cannot decrypt a keyless backup or supply overwritten/absent data.

## Processing order

| Order | Stage | Completion gate |
| --- | --- | --- |
| 1 | Intake / preflight | Complete intake and required segments |
| 2 | Source preparation | Acquisition preparation completes |
| 3 | Extraction | Finalized manifest; every planned file extracted or explicitly skipped |
| 4 | Materialization | Acquired paths registered; supported WhatsApp backups decrypted with matching material and derived files registered, or explicit per-file gaps recorded |
| 5 | Native forensic parsing | Native files and mobile bundles accounted for; priority disk records persisted |
| 6 | Recovery analysis | Derived recovery work terminal; recovery confidence retained |
| 7 | OCR | Eligible queue drained or explicitly disabled |
| 8 | Image / video observations | Eligible sources described or recorded as failed; missing vision model waits |
| 9 | Inventory / normalization / correlation | Inventory and mobile coverage persisted |
| 10 | Text-only RAG chunking | All source files considered; every normalized/priority record indexed |
| 11 | Enrichment | Complete parsed payloads and normalized records scanned |
| 12 | Graph synchronization | All evidence records and mobile correlations synchronized |
| 13 | Validation / ready | Prior gates passed; failures, unavailable priority categories and coverage gaps reported |

The controller records the completed acquisition milestones at the finalized extraction handoff. Later stages read acquired/derived evidence, not the original source image. Each job has one active stage. CPU evidence workers are capped at four. OCR and visual observation inference share one GPU permit and unload their model before releasing it. There is no embedding stage, vector-completeness gate, forensic query embedding or forensic CLIP retrieval. Existing vector columns remain compatible with older data.

`ready` means processing gates finished. `coverage_complete=false` and exception counters identify incomplete evidence coverage; ready does not prove every category on a phone was accessible.

## Priority evidence

Disk and Mobile artifact pages now have a **Priority evidence** panel with WhatsApp chats, deleted/residual WhatsApp records, web/browser activity, pictures, videos, audio, documents, other messages, emails/mailboxes, structured exports, binary fields/fragments, downloads, applications, acquired accounts/users and **Suspicious Activity** tabs. Records are paginated without discarding the remaining dataset. Source records retain file path, available source SHA256, database table/row and evidence state. Attachment links distinguish exact path matches from filename candidates.

- **Disk web/WhatsApp:** acquired Chromium, Firefox and Safari sources; visits, saved URLs, bookmarks, downloads, cookies, login metadata and search records; WhatsApp links in messages and web documents; supported acquired WhatsApp databases/backups and their media references. URL references are distinguished from actual visits. Browser storage files are retained and explicitly identified when their format/encryption prevents message decoding. Preserving WhatsApp Web storage does not by itself decrypt its chats.
- **Android priority:** WhatsApp database bundles, browser databases and WhatsApp media are scheduled ahead of other bundles. SQLite WAL/journal companions are replayed in a disposable working copy. Supported WhatsApp backup decryption uses acquired matching keys; residual candidates retain their recovery confidence and review state.
- **Photos/media/documents:** broad shared-storage collection, expanded document formats including macro-enabled Office, emails and ebooks, MIME-based recognition of extensionless media/documents, and source deletion flags. Android MediaStore entries include trash references, labelled **reference only** when they do not establish recovery of file bytes. They are visible alongside acquired media records.
- **RAG:** complete parsed text, all OCR rows, normalized records and media descriptions use the fixed 2500/800 character policy, including source headers inside the chunk window. Derived profile/OS facts use the same policy. Old-policy chunks are replaced once and resumed batches do not duplicate records. Unsupported formats and files without readable text remain explicit exceptions.

For a live Android **File System / Full File System** collection, the adapter now uses already available `su` or root access to stream priority private app data before collecting broad shared/private trees. This fixes the case where ordinary `adb pull` ran as the unprivileged shell even though root access was available. It does not root or unlock the handset. Logical/shared-storage collection alone cannot read inaccessible private WhatsApp/browser databases. Encrypted backups without matching keys, overwritten deleted bytes, unreadable sources and unsupported formats remain acquisition/processing gaps. A zero count describes this acquisition; it is not proof that the handset had no such content.

SQLite reads keep the existing 768 MB ceiling and record an exception if exceeded. Media streaming keeps the existing default 20 GiB probe ceiling (`ARTIFACT_MEDIA_PROBE_MAX_BYTES`); oversize/undecodable media is reported rather than silently skipped.

## Suspicious Activity observations

The new category stores descriptions and concrete visible review signals for both Disk and Mobile images/videos. It can highlight visible weapons/violence, credential exposure, financial documents or another visible detail needing examiner attention. A filename is not used as visual proof. OCR-based signals retain the actual text excerpt. Model output is treated as a pending examiner interpretation, not a finding of intent or an offence.

Each visual observation retains source path, artifact id, source SHA256, model, derivative frame SHA256 and a stored PNG that can be opened for comparison with the original. Video entries use actual decoded frame timestamps. A dedicated **Suspicious Activity** report section follows section C. Each candidate has source references, an explanation and, for acquired image/video observations, the verified retained picture or sampled video frame. A separate editable examiner-observations page is included in the preview, PDF and Word export. Text/message, email, browser/download/file and acquired application-record rules also contribute candidates. Source captions remain separate from examiner interpretation. The artifact page retains the source-linked media-observation Markdown download. Report fallbacks no longer infer rooting, malware, payment activity or media contents from inventory totals.

Video defaults review a frame every 10 seconds plus the final available sample; `FORENSIC_VIDEO_MAX_FRAMES=0` removes a sample-count cap. This is sampled-frame coverage, not analysis of every video frame. Animated images review the first frame. Images are presented to the model as EXIF-oriented derivatives up to 1536 pixels; the original evidence remains available. Sampling/size limits are retained in observation metadata. Examiner verification of the original is required before using a description as a formal finding.

## Apply on the central host

Pause active Disk/Mobile jobs before updating a live bind-mounted project. Keep deployment-local credentials, connection settings, drive overlays and evidence directories. Merge the following forensic settings into the existing `.env`; do not overwrite deployment connection settings with archive defaults.

```dotenv
PIPELINE_SEQUENTIAL=true
EXTRACT_THEN_PROCESS=true
PHASE3_STREAM_DURING_EXTRACT=false
PHASE3_STREAM_OCR_DURING_EXTRACT=false
PHASE3_STREAM_RAG_DURING_EXTRACT=false
PARSE_DRAIN_INTERLEAVE_RAG=false
PARSE_WORKERS=4
PARSE_PARALLEL_BUCKETS=1
PROGRESS_AGENT_INTERVAL_SECONDS=15
PROGRESS_AGENT_JOB_BATCH=200
FORENSIC_STAGE_IDLE_TIMEOUT_SECONDS=300
EXTRACT_READ_SEMAPHORE=4
OCR_CPU_WORKERS=4
OCR_PARALLEL_BUCKETS=0
OCR_GPU_ONLY=true
OCR_DEVICE=cuda
OCR_DOCUMENTS_ONLY=false
RAG_EMBEDDING_ENABLED=false
RAG_CHUNK_SIZE=2500
RAG_CHUNK_OVERLAP=800
GPU_HEAVY_MAX_CONCURRENT=1
MOBILE_WORKER_DB_POOL_SIZE=6
MOBILE_WORKER_DB_MAX_OVERFLOW=4
FORENSIC_MEDIA_REVIEW_ENABLED=true
FORENSIC_MEDIA_VISION_MODEL=qwen3.5:9b
FORENSIC_VIDEO_SAMPLE_SECONDS=10
FORENSIC_VIDEO_MAX_FRAMES=0
FORENSIC_MEDIA_VISION_TIMEOUT_SECONDS=300
```

The forensic code enforces text-only RAG and the chunk policy even if an old deployment retains an embedding flag. OCR and visual observations still require their configured models. The observation worker checks the local Ollama model's advertised vision capability before proceeding. Missing/non-vision models leave that stage waiting with a clear message. Use a locally installed image-capable model or prepare the configured model with the script option below; this can download a substantial model.

From PowerShell in the updated root, review the commands:

```powershell
.\scripts\Apply-Disk-Mobile-Serial.ps1 -DryRun
```

Apply to currently running Disk/Mobile products:

```powershell
.\scripts\Apply-Disk-Mobile-Serial.ps1 -PrepareVisionModel
```

To apply the new parsing, observations and chunk policy to completed historical cases as well:

```powershell
.\scripts\Apply-Disk-Mobile-Serial.ps1 -PrepareVisionModel -ReprocessReady
```

`-ReprocessReady` resets derived processing stages from parsing onward for finalized ready/completed/report-ready jobs in the selected products. It retains acquisition evidence and completed visual observations, and retries failed media units while retaining their partial frame observations. Paused jobs remain paused until resumed. Reprocessing can take time proportional to acquired evidence.

For stopped products, select them explicitly:

```powershell
.\scripts\Apply-Disk-Mobile-Serial.ps1 -Products @("forensic", "mobile-android", "mobile-ios") -PrepareVisionModel
```

Use `-ForensicProjectName` for a different existing Disk Compose project and `-ComposeOverrides` for deployment overlays. The script builds application images, recreates selected APIs/workers, migrates tenant schemas and adopts finalized active jobs. A running gateway is rebuilt for the UI; `-SkipGateway` leaves it running. PostgreSQL, Redis and evidence volumes stay in place. Existing worker service names containing `rag` are retained for deployment compatibility; forensic stage dispatch no longer runs embedding work.

Separate migration/model checks inside a product API are also available:

```powershell
docker compose --project-directory . -f services/forensic/docker-compose.yml exec -T api python /scripts/migrate-forensic-serial.py --adopt-active --check-vision-model
```

Limit a historical reprocess to a tenant with `--schema <tenant_schema> --reprocess-ready`. The migration removes the obsolete vector-pending index and installs new priority/media tables. Existing embedding-stage deliveries are held without loading a model. Older layouts are upgraded under the same execution lock used by workers, retaining acquisition/materialization milestones and resetting derived stages. Old progress reads show that reprocessing is required.

## Verification and cleanup

Release 5 verification: **235 regression checks and 9 acquisition checks pass**. Actual CLI runs verify independent fixture authentication and correctly report absent phone/GPU as blocked. PowerShell grammar and Python 3.11 syntax pass; Windows native execution remains a host check.

The preceding report release verification: **195 focused tests and 25 platform/resource-control tests pass**. The checks cover supported mailboxes and structured exports, full Unicode text, an 8,104-row message database, conservative source rules, actual picture bytes in PDF/Word, examiner notes, one-minute stall decisions and cancellation confined to the owned subprocess.

PostgreSQL/WASM integration checks pass for serial ordering/upgrades, progress timestamps, Suspicious Activity persistence, report checkpoint serialization, dependency retries, report pause races and WhatsApp recovery/browsing. Independent crypt12/14/15 vectors and the local WhatsApp recovery CLI pass. Disk and Mobile synthetic reports render as corresponding 16-page A4 PDFs and Word documents, with source-image captions and an observations page; rendered pages were inspected. TypeScript and unified, Disk, Android, iOS, legacy Mobile and vulnerability frontend builds pass. Python 3.11 syntax, new-module lint, PowerShell grammar and archive integrity checks are recorded in the manifest.

The earlier broader regression results and their original-upload failures remain documented in `WHATSAPP-RECOVERY.md`; they are historical checks, not release 4 pass counts. Real CUDA vision inference, live devices and Docker services are pending host acceptance. Test descriptions and retained source-image bytes are synthetic fixtures, not recovered user evidence.

The archive removes generated bytecode, caches, build metadata, dated diagnostics/logs, obsolete backup files, the retired healing panel and the unused performance-agent module. Useful diagnostics scripts, source, dependency lockfiles and test fixtures remain. Removal lists, source changes and scanner-preservation hashes are in `DISK-MOBILE-SERIAL-MANIFEST.json`.

After deployment, reprocess existing evidence and generate a new report to create the new section. Saved historical reports are not silently rewritten.

## Central-host acceptance pending

Docker deployment, live Android/iOS acquisition, real NVIDIA/Ollama inference and Redis/MinIO/Neo4j integration were not available here. These previous acceptance steps remain pending; the release does not claim they passed.

On the central host, verify one Disk case and each deployed Mobile product. For Android, use a known acquisition with WhatsApp current/deleted fixtures, matched backup keys, browser URLs, existing/deleted photos, videos/audio and several document formats. Compare captured source/record counts, open linked evidence, check descriptions against original images/frames, confirm report hashes/timestamps, test pause/resume and confirm OCR/vision model unload. Review every zero priority category and validation exception. Keep the existing deployment as a rollback copy until these checks pass. No destructive down-migration is required.

Model API references: [Ollama vision input](https://docs.ollama.com/capabilities/vision), [configured vision model](https://ollama.com/library/qwen3.5:9b). Android access context: [Android storage overview](https://developer.android.com/training/data-storage).
