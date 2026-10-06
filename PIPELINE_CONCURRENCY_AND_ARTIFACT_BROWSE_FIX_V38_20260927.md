# Polaron V38 - Pipeline Concurrency, PostgreSQL Contention and Artifact Browse Fix

Date: 2026-09-27

## Problems fixed

1. Disk-extraction shards could exhaust the worker SQLAlchemy QueuePool because the disk worker ran multiple Celery processes and each process also used an internal extraction thread pool, while the worker DB pool was only 2 + 2 overflow. Committed log/heartbeat writes opened additional sessions.
2. Parse shards could deadlock while artifact/parser writes and `jobs.pipeline_progress` updates acquired locks in different orders.
3. `parse_drain_sync` contained a conditional self-import of `parse_drain_task`, which made the symbol local to the function and caused `UnboundLocalError` on paths that referenced it before that import executed.
4. Every streamed parse shard could receive the full `PARSE_WORKERS` thread budget, and the whole-job parse drain could overlap active streamed shards. This multiplied threads instead of enforcing the intended global parse budget.
5. Duplicate deliveries of the same parse/phase-3 shard could execute concurrently.
6. Artifact Explorer counts and browse rows were not always the same evidence domain. Parsed-record artifacts (mail messages, browser/social/cloud records, USB/RDP records and carved evidence) could have a positive AXIOM count but an empty second column because the UI queried only `job_artifacts`. Legacy EML rows could also have NULL extension/MIME even though the source path ended in `.eml`/`.emlx`.

## Pipeline changes

- Added Redis single-flight locks per parse shard and phase-3 shard. Duplicate deliveries are skipped instead of repeating the same work.
- Parse drain now waits while streamed parse-shard locks are active.
- Parse worker thread budget is divided across the configured shard fan-out. With `PARSE_WORKERS=16` and `PARSE_PARALLEL_BUCKETS=4`, each active shard receives about four parser threads instead of sixteen.
- Parser/artifact writes are committed before cosmetic job-progress updates. Progress updates are elected with a non-blocking PostgreSQL transaction advisory lock; a shard skips a progress write if another shard is already updating it.
- Removed the conditional self-import that caused `parse_drain_task` to be unbound. Requeueing now uses the Celery task name through a helper.
- Committed disk-build log writes are serialized within a worker process, and heartbeat lock order is standardized (`jobs` row before disk-build log).
- Added service-specific database pools: disk worker defaults to 8 connections + 4 overflow / 90s timeout; parse worker defaults to 4 + 4 / 60s. Other worker pools remain bounded.
- Added a single-flight background signature-carve rebuild task for legacy jobs whose count inventory exists but exact-offset browse cache is absent.

## Artifact Explorer changes

- Catalog selections first query the first-class virtual evidence provider before falling back to backing-file SQL. This makes parsed messages/records viewable, not only their container/database files.
- EML(X) browse keeps indexed extension/MIME predicates and adds filename/path suffix parity for older rows not yet MIME-backfilled.
- If a carve-backed category has a persisted positive count but its exact-offset browse cache is missing, the API returns a rebuilding state and queues one background rebuild instead of returning a misleading positive count with an empty result set.
- Frontend shows the rebuild state and automatically retries that selected category. The disk image is not re-downloaded or re-extracted.

## Existing V37 indexes retained

V38 keeps the V37 Artifact Explorer PostgreSQL indexes, including job/path/name/extension/MIME/pending-work indexes and optional trigram search indexes. The reported QueuePool and deadlock failures were primarily concurrency/pool-size/lock-order issues rather than missing basic browse indexes.

## Performance note

A 50 GB image in 30 minutes requires roughly 27.8 MB/s sustained source-to-extraction throughput. V38 removes avoidable database waits, duplicate shard work and parser-thread oversubscription. Actual end-to-end time still depends on E01 compression, storage throughput, file count/type, OCR volume, parser cost, GPU model throughput and enabled enrichment stages; therefore the 30-minute number must be verified on the target server with a representative 50 GB image.

## Deployment

Recreate the affected services so the service-specific database pool environment values take effect. If the V37 indexes were not previously applied, run the V37 search-index installer/verification scripts first.
