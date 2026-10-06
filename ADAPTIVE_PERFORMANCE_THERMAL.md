# Adaptive Performance, Semaphore and Thermal Control

This revision makes forensic throughput adaptive instead of relying only on static Celery worker counts.
It does **not** change evidence selection, hashing, extraction checkpoints, parser output, or report content.

## Resource model

The host now has independent lanes:

1. **CPU-heavy lane** — disk image extraction, mobile dump extraction, materialization/finalization.
2. **GPU-heavy lane** — GLM OCR and RAG embedding/model work.
3. **CPU parse fan-out** — artifact parsing with adaptive local worker limits.
4. **LaptopScanner IP fan-out** — OpenVAS target workers with a dynamic semaphore limit.

CPU and GPU lanes remain independent. A busy GPU does not stop disk extraction or parsing. A busy disk build does not stop OCR/RAG when the GPU has safe headroom.

## Adaptive host semaphore

`backend/app/services/adaptive_semaphore.py` provides:

- Redis-backed host-wide permits with TTL and heartbeat.
- Live capacity from CPU load, available RAM, CPU temperature, GPU temperature and VRAM.
- Dynamic local caps for disk readers, mobile readers and parse workers.
- Cooperative backoff for extraction shards that become hot after they have already started.
- Safe capacity shrinking: all configured live leases are counted before new admission, so a 2 -> 1 thermal reduction cannot temporarily run two jobs.

### Cross-stack coordination

By default, each stack falls back to its own `REDIS_URL`. If Forensic and Mobile Extract run on the **same physical host**, point both stacks at one Redis instance:

```env
RESOURCE_GOVERNOR_ENABLED=true
RESOURCE_GOVERNOR_REDIS_URL=<redis-url-reachable-from-both-stacks>
RESOURCE_GOVERNOR_GROUP=aetheris-host
```

On Docker Desktop a reachable published Redis can be used, for example the forensic Redis published on host port `6380`. On Linux, use a reachable host/bridge address, a shared Docker network, or an external Redis service.

Use the **same** `RESOURCE_GOVERNOR_GROUP` only for workloads sharing the same physical CPU/GPU.

## GPU policy

`GPU_HEAVY_MAX_CONCURRENT=2` is now a ceiling, not a guarantee.

- Laptop/tight profile or GPU VRAM <= ~12.5 GB: **1 heavy CUDA session**.
- 16 GB+ / 20 GB+ cards: up to **2** only while cool.
- If free VRAM falls below 8 GB: second heavy session is not admitted.
- At `GPU_THERMAL_PAUSE_C`: no new GPU-heavy session is admitted.
- OCR is fail-closed on the GPU semaphore and is requeued instead of running anyway.
- Existing per-batch GPU thermal control remains active.

This prevents OCR + RAG from fighting for VRAM on a 12 GB laptop while still allowing CPU extraction/parse to continue.

## Disk and mobile image extraction

`MAX_CONCURRENT_DISK_BUILDS` is treated as a configured ceiling. The previous single global CPU-heavy lock no longer serializes every build.

The effective limits are adjusted by host profile and live pressure. Inside each extraction job:

- Disk/mobile reader fan-out is capped before the pool starts.
- Long-running shard workers re-check host pressure periodically and use small cooperative sleeps when the host heats up.
- Shard count/checkpoint layout remains stable for resume safety.

This keeps high I/O parallelism on a cool workstation but avoids multiplying readers across several cases on a hot or RAM-constrained laptop.

## LaptopScanner policy

The scanner still scales normally to 2/3/4 IP workers by CPU count, but the admission limit now reacts to CPU temperature, CPU utilization, load average and available RAM:

- **cool**: normal 2-4 IP workers.
- **warm**: up to 3 IP workers.
- **hot**: up to 2 IP workers and one scan job.
- **critical**: one IP worker and one scan job.

Existing OpenVAS work is not killed. The dispatcher simply stops filling new slots until the host recovers.

Recommended defaults:

```env
MAX_CONCURRENT_SCAN_JOBS=2
SCAN_IP_PARALLELISM=auto
SCAN_CPU_THROTTLE_C=84
SCAN_CPU_PAUSE_C=92
GVM_MAX_HOSTS=4
```

If a scanner container cannot read host thermal sensors, CPU utilization/load still provide protection. `SCAN_HOST_TEMP_C` is available for environments that inject a host temperature value.

## UI and observability

The forensic pipeline banner now shows:

- GPU used / live-capacity slots.
- `thermal hold` when live GPU capacity reaches zero.
- CPU-heavy used / live-capacity slots.

The Performance Agent also records distributed semaphore snapshots in orchestration state.

## Important deployment notes

After replacing the project, rebuild/recreate the Python worker containers so the new governor is loaded. For cross-stack coordination, verify both stacks use the same reachable resource-governor Redis URL.

The governor is designed to change **concurrency only**. It does not skip evidence because the system is hot; it slows or defers admission and continues/resumes the same forensic work.

## Client/server disk-image residency (2026-09-24)

- **Server-local E01/EWF/raw**: register and process in place; no browser upload and no automatic deletion of the original server evidence.
- **Client-side disk image**: Download Agent uses a bounded **5-file concurrent upload pool**. Every later disk agent is gated until all selected files are present.
- Client disk images are staged once on the forensic server filesystem rather than copied a second time to object storage before extraction.
- Client staging is deleted only after verified pipeline success; paused, failed, or interrupted jobs retain the uploaded source for resume/retry.

## Disk-image source residency: server-local vs client-upload

Disk-image intake now has an explicit residency contract:

### Server-local disk image

When the E01/EWF/raw image is already on a disk visible to the forensic server/host:

- register the source path only;
- do **not** upload or copy the image into the browser-upload staging area;
- start disk build/extraction directly against that path;
- mark `disk_source.intake=server_local` and `cleanup_policy=never_delete_source`;
- client-upload cleanup is forbidden from deleting the original server-side evidence.

This is the preferred path for large images already attached to the forensic server.

### Client-side disk image

When the image is selected from a remote/client browser:

- the Download Agent opens before the first byte arrives;
- uploads use a bounded semaphore/worker pool of **5 concurrent image files**;
- later forensic agents remain blocked until **all selected segments are present** on the server;
- disk-image uploads are staged once under `DATA_ROOT/uploads/<job>/intake` and are not duplicated into object storage before extraction;
- registration/extraction starts only after the final upload completes successfully;
- uploaded source images are retained on failure/interruption for resume;
- after verified pipeline success (`status=ready`, `progress=100`, pipeline phase `complete`, extraction complete), the inbound staging tree is deleted;
- extracted artifacts and normal permanent job storage are not deleted.

Cleanup is idempotent: rerunning cleanup after the staging folder is already gone is treated as success.
