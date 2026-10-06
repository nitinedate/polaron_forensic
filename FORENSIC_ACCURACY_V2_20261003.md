# Polaron Forensic Accuracy Review and Patch

**Version:** 2026-10-03  
**Priority:** Evidence accuracy and reproducibility first; preserve existing performance tuning where it does not reduce coverage.

## 1. Executive summary

This patch reviews and hardens the central Polaron server against the supplied forensic-report methodology, the current mobile extraction architecture, the laptop vulnerability scanner, and the reported resource-governor failure.

The patch does **not** manufacture missing forensic evidence. Every conclusion must be traceable to evidence present in the selected acquisition, a deterministic parser/query, and a recoverability state. Deleted-data candidates from WAL/journal/freelist/carving are kept separate from confirmed live or logically deleted records unless validation supports promotion.

Key results:

- The report-agent reference corpus now represents all **13 supplied forensic reports**, not only the previous five examples.
- Report agents receive deterministic query-planning guidance: case/job scope, coverage prerequisites, stable deduplication, recovery-state separation, provenance, and index hints.
- The `redis-capacity:6379` DNS/transport outage no longer has to defer disk/mobile extraction indefinitely. Local product guards remain active, while real shared-capacity exhaustion still fails closed.
- UFED/UFDX resolution is safer and more portable, including descriptors containing Windows absolute paths from another workstation.
- Sealed UFED/ZIP evidence can now attempt existing fail-closed WhatsApp `msgstore*.crypt12/14/15` decryption when a usable same-evidence WhatsApp key is present. No brute force or key guessing is introduced.
- PostgreSQL migration 037 is now actually included in platform migration helpers, and API startup no longer overwrites its rich search-index function with a one-index fallback.
- Vulnerability scanning defaults are accuracy-first (`full` TCP profile and `GVM_OPTIMIZE_TEST=false`) and composite report/query indexes were added.
- Existing high-throughput disk/mobile concurrency values were preserved rather than reduced to old test expectations.

## 2. Source material reviewed

The supplied reference set contains 13 reports covering workstation/disk evidence, Google Takeout/cloud evidence, email, shared data/permissions, activity/account artifacts, data reports, and a combined master report.

The corpus uses them as **methodology exemplars only**. It does not treat any source-report person, account, date, count, URL, device ID, artifact value, or conclusion as a fact for a new case.

The learned report grammar is:

`inventory -> objective -> procedure -> record-level evidence -> exclusion/deduplication -> observation -> limitation -> annexure traceability -> summary`

## 3. Report-agent and query-training changes

### 3.1 New versioned corpus

Added:

`backend/app/knowledge/report_reference_corpus/all_forensic_reports_v2.json`

The corpus contains:

- 13 source reports
- 18 objective patterns
- 13 artifact inventory families
- 15 forensic/report training rules
- 8 global query principles
- cross-section consistency rules
- cloud/email/Google Takeout objective patterns absent from the older five-report corpus

New cloud-oriented objectives include:

- Google Account Data
- Gmail Usage
- Google Drive Files
- Google Account Activity
- Google Calendar Events
- Google Connected Devices
- Google Photos/Albums
- Google Drive Shared Files
- Google Drive Shared Permissions

### 3.2 Deterministic query strategy

Each objective maps to a controlled evidence/query strategy containing:

- primary filters
- stable deduplication keys
- coverage requirements
- index hints

Global rules include:

1. The LLM must not execute arbitrary SQL. It resolves the objective to controlled/versioned collectors or report definitions using bound parameters.
2. Scope by tenant/schema and current case/job before broad artifact filtering.
3. Prefer stable native IDs or source identities for deduplication before weaker text/timestamp combinations.
4. Use indexed equality/range predicates for primary selection; use `ILIKE`/regex for discovery only after narrowing by case/job where possible.
5. Keep live/allocated, logical-deleted, trash/filesystem-recovered, WAL/journal/freelist residual, and carved/unallocated states separate.
6. Never merge unverified residual/carved candidates into confirmed deleted counts.
7. Verify collector/source coverage before making a negative conclusion.
8. Preserve source path, hash/provenance, parser/version, and native record identity needed to reproduce the finding.

### 3.3 Accuracy contract improvements

The evidence contract now requires additional derived-state information where appropriate:

- **USB/device reports**: distinct physical-device count and device identity/model. Raw interfaces/volumes are not automatically counted as different physical devices.
- **Email reports**: `account_state` separates a currently configured account from historical correspondence, browser traces, or prior usage.

This prevents two common forensic-report overstatements: overcounting one physical USB device and describing any observed email address as a currently configured account.

## 4. Disk extraction and Redis resource-governor fix

### Reported production symptom

`Extract deferred - chassis busy (resource governor unavailable: Error-2 connecting to redis-capacity:6379. Name or service not known.)`

### Root cause

The CPU-heavy extraction path already held product-local admission/thermal protection, but loss of the **shared** host-capacity Redis was configured to fail closed. A DNS/transport problem in the coordination layer was therefore promoted into an evidence-processing defer/failure condition.

### New behavior

A new setting was added:

`RESOURCE_GOVERNOR_FAIL_OPEN_ON_UNAVAILABLE=true`

When enabled:

- DNS/connection/ping failure to the shared governor logs a warning.
- Extraction continues under the existing local product guards.
- A real capacity response from the shared governor still fails closed.
- GPU behavior is intentionally unchanged.

To restore the old strict behavior, set:

`RESOURCE_GOVERNOR_FAIL_OPEN_ON_UNAVAILABLE=false`

This is intentionally a transport-outage fallback, **not** a bypass for real capacity exhaustion.

## 5. PostgreSQL query and index corrections

### 5.1 Migration 037 deployment issue fixed

The project already contained strong artifact-search indexes in:

`migrations/037_search_performance_indexes.sql`

but the platform migration helpers did not consistently apply migration 037. In addition, API startup could replace `public.apply_firm_search_indexes_v1(text)` with a minimal one-index implementation.

Changes:

- `scripts/ensure_sql_functions.py` includes migration 037.
- `scripts/apply_migrations.sh` includes migration 037.
- `scripts/apply_migrations.ps1` includes migration 037.
- `firm_schema_apply.py` creates only a guarded fallback if the rich migration function does not already exist; it no longer overwrites the migration-owned function.

### 5.2 Vulnerability-query indexes added

Migration 037 now creates composite indexes for common report/progress predicates, including:

- `(case_id, status, severity)` on vulnerability findings
- `(scan_job_id, status)` on vulnerability findings
- `(asset_id, status)` on vulnerability findings
- `(case_id, port, protocol)` on vulnerability findings
- `(case_id, primary_ip)` on vulnerability assets
- `(scan_job_id, excluded, target)` on scan targets
- `(case_id, created_at DESC)` on scan jobs
- `(scan_job_id, created_at DESC)` on scan results

The migration also analyzes vulnerability finding/target tables after index application.

### 5.3 Mobile indexing

The existing mobile normalized-artifact store already has useful job/domain/state/timestamp/artifact-family indexes. The patch does not add redundant indexes merely to increase index count.

## 6. Mobile evidence processing

### 6.1 Supported evidence graph

The code distinguishes the roles of common UFED/PA artifacts:

- `.ufd`: descriptor that can point to a `FileDump` ZIP and logical root
- `.ufdx`: evidence index/descriptor that can point to `.ufd`, `.pas`, or ZIP companions
- `.zip`: readable package/filesystem payload when it actually contains evidence
- `.pas`: native PA case object; it is not automatically a ZIP/filesystem payload

For a native `.pas`, the reliable payload normally comes from the sibling `.ufd`/FileDump ZIP or another supported readable export. The system must not pretend a proprietary PA object was fully decoded when only its container was registered.

### 6.2 UFD/UFDX portability and path safety

Cellebrite descriptors can contain absolute paths from the examiner workstation, such as Windows drive-letter paths. Those are now treated as metadata rather than trusted host filesystem paths.

Resolution now:

- handles quoted and Windows-style path strings
- resolves valid relative paths inside the evidence folder
- uses the referenced basename for portable companion-file lookup
- constrains resolution to the evidence folder
- follows a UFDX -> UFD -> FileDump ZIP graph even when the companion file was not independently registered

This fixes a common reason for “package present but artifact counts empty.”

## 7. WhatsApp and deleted-data recovery

### 7.1 Encrypted Android WhatsApp backups inside UFED/ZIP

The package inventory previously detected encrypted `.crypt*` material but did not route companion `msgstore*.crypt12/14/15` + WhatsApp key material through the existing decryptor.

The patched flow:

1. Identify actual encrypted **msgstore** backups, not unrelated `.webp.crypt14` theme/media files.
2. Locate a bounded same-evidence WhatsApp key candidate, preferring the canonical `/data/data/com.whatsapp/files/key` location.
3. Derive the supported key form using the existing vetted key-material parser.
4. Attempt the existing crypt12/14/15 decryptor.
5. Accept output only when it decodes to a valid SQLite database.
6. Parse with the normal WhatsApp DB analyzer.
7. Preserve `#decrypted` provenance in the source path.
8. Merge repeated backup counts using conservative `max()` semantics rather than summing snapshots.
9. Emit an explicit limitation if the key is absent, unusable, or the encrypted backup cannot be validated.

No password guessing, brute force, or arbitrary external key use is introduced.

### 7.2 Deleted WhatsApp/chat evidence state model

Deleted WhatsApp recovery is attempted from the evidence sources that can actually retain deleted history, including database logical state, SQLite sidecars/residual pages, historical backups, filesystem/trash recovery, and recoverable full-filesystem material.

The reporting model must distinguish:

- confirmed live/allocated row
- confirmed logical-deleted/recovered row where parser semantics support it
- trash/filesystem recovered object
- WAL/journal/freelist residual candidate
- carved/unallocated candidate
- historical backup record
- unverified residual

A historical encrypted backup is **not automatically a deleted message**. A WAL/journal/freelist string hit is **not automatically a complete deleted SQLite row**. Promotion requires parser validation and provenance.

### 7.3 Why deleted WhatsApp cannot be guaranteed at 100%

Even with correct parsing, deleted data may be unrecoverable when the acquisition never contained private app data, encryption keys are unavailable, SQLite pages were vacuumed/reused, secure deletion removed content, or the relevant filesystem blocks were not acquired.

The correct requirement is therefore: **recover all deleted data that is technically recoverable from the acquired evidence, and report the acquisition/cryptographic limitation when it is not recoverable.**

## 8. Android acquisition expectations

Best deleted/private-app recovery requires an acquisition that contains private application data and/or a full filesystem where lawful access permits it. A normal public/logical Android export cannot reveal every app-private SQLite database or deleted page simply through a better query.

The analysis stage can only recover evidence that reached the acquisition. The patch therefore keeps acquisition coverage separate from parser/report accuracy.

## 9. iPhone/iOS acquisition expectations

Readable iTunes-style backup/full-filesystem evidence can be mapped back from hashed backup files to logical application paths and parsed by the existing mobile pipeline.

For an **encrypted imported iOS backup**, merely supplying a password to the current generic importer does not make encrypted hashed files plaintext. The patch changes the preflight wording so it no longer implies otherwise. Such evidence must first be materialized by a supported decrypt/unback acquisition workflow, then passed to artifact parsing.

This is an explicit remaining capability boundary rather than a false success state.

## 10. Vulnerability scanner accuracy

### Laptop scanner

The supplied laptop scanner already has the current Nessus-fidelity path and passed its focused compatibility/fidelity tests. It already uses the full TCP profile as the default, with configurable UDP strategy and non-optimized VT execution when required for fidelity.

No source change was made to the laptop scanner simply to create a different ZIP; the verified implementation was retained.

### Central server

The central default was inconsistent with the laptop scanner (`fast` + optimization enabled). It is now accuracy-first:

- `GVM_PORT_PROFILE=full`
- `GVM_OPTIMIZE_TEST=false`

Operators can explicitly choose a faster profile when the engagement accepts reduced port coverage.

The existing Nessus/CVSS/severity fidelity implementation was retained and re-tested rather than replaced.

## 11. Performance decisions

The user's current disk/mobile performance tuning was intentionally preserved.

Two stale tests still represented old concurrency values. They were updated to the **current production tuning** rather than reducing the runtime:

- laptop CPU-heavy slots remain at the current value
- mobile reader fanout remains at the current value

The main performance-related behavior change is therefore protective/accuracy oriented:

- shared resource-governor DNS outage no longer blocks extraction when local guards are healthy
- central GVM coverage defaults are broader, which can take longer than an explicitly selected fast profile

## 12. Verification results

### Central forensic/mobile/report regression

**146 passed**

Coverage included:

- adaptive/shared resource semaphore behavior
- stale job locks
- expanded report-reference training
- evidence contracts
- Cellebrite UFED/UFDX resolution
- mobile architecture
- WhatsApp crypt handling
- mobile forensic inventory/completeness/private acquisition/counts
- severity logic
- vulnerability module/orchestrator/extended behavior

### Vulnerability focused regression

**58 passed**

### Migration/index focused checks

**2 passed**

### Laptop scanner Nessus/GMP/port/capacity regression

**34 passed**

### Python syntax/compile verification

All modified application Python modules compiled successfully.

## 13. Deployment sequence

1. Back up the PostgreSQL database and current deployment configuration.
2. Replace the central project with this patched build or merge the listed changes.
3. Confirm the desired setting:
   - `RESOURCE_GOVERNOR_FAIL_OPEN_ON_UNAVAILABLE=true` for local-guard fallback on shared governor outage.
4. Apply database migrations using the project migration helper. Migration 037 must be applied so the full search/vulnerability index function is installed.
5. Rebuild/restart affected central/mobile services using the project's normal Docker Compose deployment flow.
6. Verify Redis DNS/service naming from the Docker network anyway. The fallback prevents unnecessary extraction deferral, but the shared governor should still be restored for cross-product host coordination.
7. Run a controlled disk/mobile test case and verify:
   - job proceeds when `redis-capacity` is intentionally unavailable but local guards are healthy
   - real capacity saturation still rejects/defer appropriately
   - UFDX -> UFD -> FileDump resolution succeeds
   - encrypted WhatsApp backups clearly report either successful validated decryption or an explicit key/decryption limitation
   - recovered/deleted/unverified states remain separate in UI/report counts
8. Run a controlled vulnerability job and verify per-IP progress plus report counts against the scanner raw evidence.

## 14. Files changed

Application/runtime:

- `.env`
- `.env.example`
- `backend/app/config.py`
- `backend/app/knowledge/report_reference_corpus/all_forensic_reports_v2.json` (new)
- `backend/app/knowledge/report_reference_corpus/report_formation_training_v2.json`
- `backend/app/services/adaptive_semaphore.py`
- `backend/app/services/axiom_forensic_kb.py`
- `backend/app/services/evidence_contract.py`
- `backend/app/services/firm_schema_apply.py`
- `backend/app/services/job_locks.py`
- `backend/app/services/mobile_adapters/import_ios_backup.py`
- `backend/app/services/mobile_forensic/cellebrite_ufed.py`
- `backend/app/services/mobile_forensic/package_inventory.py`
- `backend/app/services/report_examination_narratives.py`
- `backend/app/services/report_formation_agent.py`
- `backend/app/services/report_reference_kb.py`
- `docker-compose.yml`
- `docker-compose.https.yml`
- `migrations/037_search_performance_indexes.sql`
- `scripts/apply_migrations.sh`
- `scripts/apply_migrations.ps1`
- `scripts/ensure_sql_functions.py`
- `services/mobile-android/.env.example`
- `services/mobile-android/docker-compose.yml`
- `services/mobile-extract/.env.example`
- `services/mobile-extract/docker-compose.yml`
- `services/mobile-ios/.env.example`
- `services/mobile-ios/docker-compose.yml`
- `services/vuln/docker-compose.yml`

Regression tests were updated/added for the new behavior in the corresponding `backend/tests` files.

## 15. Remaining known limitations

1. **Encrypted imported iOS backups:** need a genuine decrypt/unback/materialization stage before normal parsing; password presence alone is not plaintext access.
2. **Native `.pas`:** a proprietary PA object is not equivalent to a readable filesystem image. Reliable extraction generally requires the companion UFD/FileDump/readable export.
3. **Deleted encrypted application data:** recovery remains dependent on both residual evidence and valid cryptographic material.
4. **Acquisition coverage:** a logical/public mobile acquisition cannot be made equivalent to a full/private filesystem acquisition by SQL/RAG/query changes.
5. **RAG role:** RAG is for retrieval/correlation/narrative support. It is not the authoritative counter of artifacts. Deterministic parsers and PostgreSQL collectors remain authoritative for counts and evidence state.
6. **Shared governor fallback:** continuing under local guards during shared Redis outage sacrifices cross-product host-wide coordination temporarily; restore the shared governor even though extraction no longer needs to remain indefinitely deferred.

## 16. Accuracy-first processing flow

```text
Acquisition / image / UFED package
        |
        v
Evidence inventory + provenance + hashes
        |
        +--> acquisition coverage / key availability checks
        |
        v
Deterministic parsers and recovery analyzers
        |
        +--> live/allocated
        +--> logical deleted/recovered
        +--> filesystem/trash recovered
        +--> WAL/journal/freelist residual
        +--> carved/unallocated candidate
        |
        v
Normalized PostgreSQL evidence model
(case/job scoped, indexed, deduplicated)
        |
        +--> authoritative artifact counts / report collectors
        |
        +--> RAG index for retrieval/correlation
        |
        v
Objective-aware report agent
(query plan + evidence questions + limitations)
        |
        v
Procedure -> evidence -> observation -> limitation -> annexure trace
```

The critical rule is that RAG/LLM reasoning may explain and correlate evidence, but it must not silently replace deterministic evidence collection or promote an unverified recovery candidate into a confirmed fact.
