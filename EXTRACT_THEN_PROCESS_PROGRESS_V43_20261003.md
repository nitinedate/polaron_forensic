# Polaron Disk Pipeline - Extract Once, Then Process (V43)

Date: 2026-10-03

## Objective

Make disk-image processing deterministic and understandable for large E01/raw evidence sets:

1. Enumerate the evidence filesystem once.
2. Extract the selected forensic evidence once into immutable extracted-evidence shards.
3. Finalize the extracted-evidence manifest.
4. Only then start artifact registration, parsing, OCR, RAG, entity/graph enrichment, and artifact inventory.
5. Never let a downstream agent reopen the original image after the extraction barrier has finalized.

This change is accuracy-first. Post-extraction agents may still run concurrently where safe, but none may compete with the image walk/extraction phase.

## Root cause of the long/misleading Job Detail state

The previous runtime had several independent paths that could start downstream work while extraction was still active:

- `PHASE3_STREAM_DURING_EXTRACT=true` and `PHASE3_STREAM_OCR_DURING_EXTRACT=true`.
- Dynamic host tuning could force streaming back on even if an environment setting was changed.
- Finished extraction shards queued Phase 3 work immediately.
- The pipeline supervisor could restart materialize/parse/OCR/RAG/inventory independently while the image was still being walked.
- The orchestrator/UI intentionally preserved partial downstream progress from streaming runs.
- Extraction's phase-local 99% could become the global pipeline high-water mark, leaving the whole UI pinned near 99% even after Phase 2 started.

That is why the screenshot could simultaneously show Extraction 99%, Materialize 12%, OCR 99%, Parse 99%, RAG work, and Artifact Inventory while the filesystem walk was still reporting hundreds of thousands of files.

## New execution contract

### Phase 1 - One-time evidence extraction

**1A. Prepare evidence**
- Drive/source registration
- Segment validation
- Virtual disk open/mount

**1B. Enumerate filesystem**
- UI shows `Filesystem inventory - N files discovered`.
- No fake percentage is produced because the final denominator is not known yet.
- All post-extract agents are visibly `Waiting for evidence extraction to finish`.

**1C. Extract files**
- Once enumeration/filtering completes, the denominator is fixed.
- UI shows:
  - files extracted / files total
  - files remaining
  - bytes extracted / planned bytes
  - bytes remaining
  - extraction shard progress

**1D. Finalize evidence manifest**
- When all files are copied, extraction stays at 99% while the immutable manifest/index is finalized.
- UI explicitly says `Finalizing extracted evidence manifest`.
- `extracted_disk_uri` is the hard barrier that opens Phase 2.

### Phase 2 - Post-extraction processing

The original image is no longer the working source. Agents use the finalized extracted evidence/index.

1. Register artifacts from the extracted index (formerly shown as `Materialize`).
2. Parse forensic files.
3. OCR eligible documents/images.
4. RAG chunking/embedding.
5. Entity extraction / graph / annotation / ontology.
6. Artifact inventory and final counts.

Post-extraction concurrency remains available for performance where dependencies permit it.

## Important forensic behavior

### Original image is not re-extracted per agent

The downstream artifact-registration stage writes metadata rows from the extracted index. It does not perform a second full disk extraction.

The legacy `materialize_missing_critical_from_disk()` fallback previously could reopen the original E01/raw disk if a critical hive was missing. In strict extract-then-process mode, that fallback is blocked once `extracted_disk_uri` exists. Critical forensic paths are explicitly protected by the extraction filter, so they must be captured in Phase 1. If evidence is genuinely absent/unreadable, the correct outcome is a forensic limitation, not a hidden second read of the source image.

### Existing jobs created by the older streaming build

They may already contain partial artifact/parse/RAG rows. Those rows are not deleted. During Phase 1 they are parked in the UI. After extraction finalizes, the full extracted index is upserted with `ON CONFLICT`, missing artifact rows are added, and usable prior work can be reused.

Extraction checkpoints and cached enumeration plans are preserved. A worker restart should resume completed shards rather than intentionally re-enumerating/re-extracting everything.

## Progress/UI changes

The Job Detail page now separates phase semantics instead of presenting every agent as simultaneously active.

During extraction:
- progress bar label: **Extraction progress**
- banner: **Phase 1 - One-time evidence extraction**
- explicit enumeration/copy/finalization state
- exact file and byte remaining counts after the plan is known
- all downstream stages show a waiting reason
- supervisor lane/huddle noise is hidden while the extraction barrier owns the machine

After extraction:
- progress bar label returns to **Overall pipeline**
- banner: **Phase 2 - Post-extraction processing**
- current/next agent is shown
- number of required stages remaining is shown
- stage detail text is visible under every process row
- `Materialize` is renamed **Register artifacts** to describe what it actually does

## Overall-percentage correction

Extraction percentage is now treated as phase-local. The first Phase 2 orchestration snapshot resets the extraction-owned high-water mark. Also, legacy `jobs.progress_pct=100` written when disk extraction completes is ignored when orchestration data exists.

This prevents the complete pipeline from falsely remaining at 99% while Phase 2 is only beginning.

## Runtime settings

Default:

```env
EXTRACT_THEN_PROCESS=true
PHASE3_STREAM_DURING_EXTRACT=false
PHASE3_STREAM_RAG_DURING_EXTRACT=false
PHASE3_STREAM_OCR_DURING_EXTRACT=false
```

The dynamic host-capacity planner also forces these values, so performance auto-tuning cannot silently re-enable overlap.

`PIPELINE_SEQUENTIAL_AGENTS=false` remains unchanged. This is intentional: the hard sequence is **Extraction -> Phase 2**; safe post-extraction concurrency is retained.

## Performance implications

For the screenshot scenario, extraction was sharing storage/CPU/database resources with materialize, parse, OCR, RAG and inventory. The new barrier gives the image walk and shard writer exclusive priority during Phase 1. This should reduce I/O contention and make elapsed time much more predictable.

No fixed completion time should be promised from image size alone. A 250 GB image containing 750,000+ small/fragmented files can take very different time from a 250 GB image containing large contiguous files. E01 compression, source HDD/SSD speed, destination MinIO speed, filesystem damage, unreadable records, hashing policy and file count all materially affect extraction time.

The important change is that the UI now exposes the real denominator once known and downstream workloads cannot obscure or slow the source extraction phase.

## Files changed

- `.env`
- `docker-compose.yml`
- `docker-compose.https.yml`
- `backend/app/config.py`
- `backend/app/services/host_capacity.py`
- `backend/app/services/extracted_disk.py`
- `backend/app/services/disk.py`
- `backend/app/services/pipeline_supervisor.py`
- `backend/app/services/pipeline_orchestrator.py`
- `backend/app/services/phase3_pipeline.py`
- `backend/app/services/artifact_materialize.py`
- `frontend/src/lib/types/forensic.ts`
- `frontend/src/lib/orchestrationStages.ts`
- `frontend/src/components/forensic/AgentPipelineBanner.tsx`
- focused regression tests

## Verification

Focused V43 tests: **10 passed**.

Focused pipeline-orchestrator tests: **5 passed** (28 deselected).

Focused host-capacity tests: **2 passed** (7 deselected).

All backend application Python modules compile successfully.

TypeScript parse/syntax check on the modified frontend files found no TS1xxx syntax errors. A complete frontend build cannot be performed in this supplied workspace because frontend dependencies are not installed; the compiler reports missing external modules such as React/clsx/lucide rather than syntax errors.

A broader static suite still reports **50 passed / 16 failed**, and the same **16 failures occur on the untouched pre-V43 baseline**. They are pre-existing stale-contract assertions unrelated to this change. The extraction-plan runtime suite also cannot collect in this workspace because the available Python environment does not include the `zstandard` package required by `extracted_disk.py`.

## Deployment note

Rebuild/restart the API, disk/parse/RAG/OCR/agent workers and frontend so all components use the same barrier contract. Do not deploy only the frontend or only the worker.

For an already-running large job, stop/restart the central stack normally and resume the job rather than deleting it. The extraction checkpoint is designed to reuse completed shards and the cached enumeration plan.
