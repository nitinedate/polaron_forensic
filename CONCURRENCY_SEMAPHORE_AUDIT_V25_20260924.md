# Aetheris concurrency / semaphore audit V25 — 2026-09-24

## Scope
Reviewed Disk Forensics, Android, iOS, mobile/disk image extraction, client upload, parse/materialize, OCR, RAG/CLIP, reporting, PostgreSQL pools, shared host-capacity Redis, and LaptopScanner IP concurrency.

## Concurrency model after V25

### Independent product state
- Disk, Android and iOS keep independent PostgreSQL, Redis job brokers, MinIO data and Celery queue namespaces.
- LaptopScanner keeps its own local adaptive IP semaphore and does not consume the forensic host Redis semaphore.
- Client disk-image upload uses its own five-file browser worker pool and does not hold extraction/GPU permits while transferring.

### Shared physical-host coordination
Only CPU-heavy extraction/materialization and GPU-heavy model work use the shared capacity coordinator. CPU-heavy and GPU leases use different Redis resource namespaces, so CPU extraction does not lock GPU OCR/RAG and GPU work does not lock uploads/reports/normal API requests.

## Bottlenecks found and resolved

1. **One product could monopolize all host CPU/GPU permits.**
   - Added product-lane demand/fair-share admission. A product can use full capacity when alone, but leaves capacity for waiting Disk/Android/iOS lanes when competition appears.

2. **Different local slot ceilings could hide higher-index host leases.**
   - Added host-wide slot namespace ceilings independent of product-local tuning (`RESOURCE_GOVERNOR_CPU_MAX_SLOTS`, `RESOURCE_GOVERNOR_GPU_MAX_SLOTS`).

3. **Semaphore heartbeat stopped forever after one transient Redis error.**
   - Heartbeats now retry until ownership is lost or the lease is released.
   - Refresh/delete operations use token-atomic Lua checks to prevent an expired old owner from touching a replacement lease.

4. **Release during a short Redis outage could leave a stale permit until TTL.**
   - Shared and local releases now retry briefly before falling back to TTL recovery.

5. **Module-global local lease ownership was unsafe with overlapping threads.**
   - Local CPU/GPU leases are now per-thread/context and cannot overwrite or release another task's token.

6. **Shared permit was acquired before product-local permit.**
   - Lock order is now local-first, shared-second. A task waiting on its own product lane cannot reserve scarce host capacity.

7. **Parse tasks shared the same Celery process pool as extraction.**
   - Added `disk-parse`, `android-parse`, `ios-parse` workers/queues.
   - Parse, Phase 3 post-processing, inventory and CPU enrichment no longer occupy extraction worker processes.
   - Startup and dynamic-drive mount scripts include the new parse workers.

8. **Idle GPU workers retained BGE/GLM/CLIP models after releasing the GPU semaphore.**
   - Shared-host mode defaults `GPU_RELEASE_MODEL_AFTER_TASK=true`.
   - RAG, OCR and CLIP release CUDA model memory while the GPU permit is still held, then release the permit.
   - Dedicated GPU servers may set it to false if warm-model latency is preferred and VRAM isolation is not required.

9. **Per-process PostgreSQL pools were oversized for prefork microservices.**
   - Worker defaults reduced to 2 + 2 overflow.
   - API defaults use 10 + 10 overflow.
   - This avoids hundreds of potential connections across Disk/Android/iOS workers.

10. **Production HTTPS API inherited the worker-sized DB pool.**
    - HTTPS API now explicitly uses the API pool defaults.

## Important non-blocking guarantees
- `cpu_heavy` and `gpu` are separate shared resources.
- Parse workers are a separate Celery pool from extraction workers.
- Reports are a separate queue and do not hold CPU/GPU extraction semaphores.
- Client uploads do not acquire CPU/GPU semaphores; five uploads per job can continue while extraction/GPU work is active.
- Android and iOS have distinct product-local queues and Redis brokers; they share only short-lived physical-host capacity leases.
- LaptopScanner IP slots are local to the scanner host; unavailable/error IPs release their slot and do not block the next IP.

## Validation performed
- 151 runnable backend concurrency/isolation/client/mobile/GPU scenarios passed; one Celery-import-dependent test was deselected because Celery is not installed in this sandbox.
- 41/41 LaptopScanner tests passed.
- Focused semaphore/isolation suite passed after queue/model changes.
- Python source compilation passed.
- Docker Compose YAML parsing passed for Disk, HTTPS, Android, iOS, capacity coordinator and LaptopScanner stacks.
- Full backend collection is not possible in this sandbox because runtime packages such as `psycopg2`, `zstandard`, and `celery` are absent and network installation is unavailable.

## Recommended shared-host defaults
```env
RESOURCE_GOVERNOR_ENABLED=true
RESOURCE_GOVERNOR_REDIS_URL=redis://host.docker.internal:6389/0
RESOURCE_GOVERNOR_GROUP=aetheris-host
RESOURCE_GOVERNOR_CPU_MAX_SLOTS=8
RESOURCE_GOVERNOR_GPU_MAX_SLOTS=4
GPU_RELEASE_MODEL_AFTER_TASK=true
WORKER_DB_POOL_SIZE=2
WORKER_DB_MAX_OVERFLOW=2
API_DB_POOL_SIZE=10
API_DB_MAX_OVERFLOW=10
PARSE_CELERY_CONCURRENCY=4
MOBILE_PARSE_CONCURRENCY=2
```

Actual live admission still shrinks automatically according to CPU/RAM/GPU/thermal capacity.
