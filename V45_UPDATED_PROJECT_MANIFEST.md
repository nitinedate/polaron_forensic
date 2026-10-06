# V45 updated project — what changed (2026-10-04)

Full details: `POLARON_EXPERT_REVIEW_V45_20261004.md`. Unified diffs: `patches_v45/`.

## Backend (disk / mobile / OCR)
| File | Change |
|---|---|
| `backend/app/services/extract_shard_v45.py` | NEW — streaming, DB-free, semaphore-gated shard worker (replaces `_shard_worker`) |
| `backend/app/services/extract_os_vendor_noise.py` | NEW — AXIOM-aligned OS/vendor tree exclusion (`EXTRACT_OS_VENDOR_TREES=skip`) |
| `backend/app/services/extracted_disk.py` | wires V45 worker, event bus drained by the flusher, source-aware reader cap, vendor filter hook, `vd_plan`/`part_prefix` in payloads |
| `backend/app/services/virtual_disk.py` | `open_virtual_disk_from_paths()` (no DB) + `vd_plan()` |
| `backend/app/services/ocr_gpu.py` | evicts Ollama before GLM-OCR load (`GPU_THERMAL_UNLOAD_OLLAMA_BEFORE_OCR`) |
| `backend/app/services/dual_rag_index.py` | **V45.1** — takes the GPU lane only when `RAG_EMBEDDING_ENABLED=true`; CPU chunking no longer collides with OCR ("RAG deferred — GPU slot busy … after 0s") |
| `backend/app/services/job_locks.py` | **V45.1** — `describe_gpu_lane_state()`: lock-timeout message now says who holds the lane (reason/pid/age), thermal pause, or stale lease |
| `backend/app/services/mobile_forensic/whatsapp_crypt.py` | REPLACED — correct key offset (126), crypt15 HKDF, crypt14/15 header walk, diagnostics |
| `backend/app/services/mobile_forensic/parsers/whatsapp_modern.py` | NEW — modern msgstore resolver, JID joins, media, revoked/quoted/FTS deleted recovery, calls |
| `backend/app/services/mobile_forensic/parsers/messaging.py` | routes modern DBs to the resolver; freelist carve on decrypted bytes; decrypt-failure artifact |
| `backend/app/services/inventory_liveness.py` | **V45.2** NEW — lock heartbeat + sub-step liveness log for the whole inventory run |
| `backend/app/services/catalog_artifact_runner.py` | **V45.2** — run wrapped in liveness; step markers (results schema, catalog ensure, scope rows, census, path index, counting); step-timing summary line; liveness lines count as activity |
| `backend/app/celery_factory.py`, `forensic_common/pipeline_routing.py` | **V45.2** — inventory task on its own `disk-inventory` queue (was sharing `disk-parse` with parse/enrich) |
| `diagnostics/diagnose_inventory_stall.py`, `Diagnose-Inventory-Stall.cmd` | **V45.2** NEW — one-shot stall diagnosis (celery/redis/queues/pg_stat_activity/logs) |
| `backend/app/parsers/emlx_sidecar.py` | NEW — Apple Mail plist flags/dates + `Attachments/` sidecars |
| `backend/app/parsers/email_mime_parser.py` | preview includes `emlx` block + sidecar attachments |
| `backend/tests/test_whatsapp_crypt.py` | fixed: test had encoded the wrong key offset |
| `backend/tests/test_whatsapp_crypt_v45.py` | NEW — 9 tests |

## Deployment
| File | Change |
|---|---|
| `docker-compose.yml`, `services/mobile-android/docker-compose.yml`, `services/mobile-ios/docker-compose.yml` | **V45.3** — `init: true`, `stop_signal: SIGTERM`, `stop_grace_period: 120s` on every worker (30 s on api); `REMAP_SIGTERM=SIGQUIT` (Celery cold shutdown); `evidence_staging` named volume mounted as `/host/${EVIDENCE_STAGING_LETTER:-z}` on api/worker-disk/worker-parse |
| `backend/app/celery_factory.py` | **V45.3** — `worker_shutting_down`/`worker_process_shutdown` hooks release GLM-OCR, embedder, CUDA cache and Redis heavy leases; `worker_cancel_long_running_tasks_on_connection_loss` |
| `scripts/docker-engine-recovery.ps1` | **V45.3** NEW — detects "did not receive an exit event", `rm -f`, Docker Desktop engine restart, retry |
| `scripts/start-stack.ps1` | **V45.3** — stops `worker-*` with 120 s grace before `up`, runs `up` through the recovery wrapper; new `-AutoRecoverEngine` switch |
| `script_docker/start_docker.ps1` | **V45.3** — passes `-AutoRecoverEngine` (production) |
| `scripts/stage-evidence.ps1`, `Stage-Evidence.cmd` | **V45.3** NEW — copy an evidence folder once into the VM volume (shows as drive Z:); `-Verify` compares SHA-256 |

| File | Change |
|---|---|
| `docker-compose.yml` | **V45.2:** `worker-disk` consumes `disk-build,disk-inventory`, `worker-parse` consumes `disk-parse,disk-inventory`. V45: worker DB pool 2+2 → 4+8 / 90 s; `/scratch` bind mount on `worker-disk` (`EXTRACT_SCRATCH_HOST_DIR`) |
| `.env` | **V45.1:** `DEFER_BACKGROUND_RAG_WHILE_OCR=true`, `GPU_HEAVY_LOCK_WAIT_SEC=180`. V45: extraction tunables (`EXTRACT_READ_SEMAPHORE=8`, HDD readers/chunks, scratch, vendor filter), GPU admission (`GPU_HEAVY_MAX_CONCURRENT=1`, OCR 0.80 / RAG 0.35), pool vars. **Create `F:/PolaronBackup/forensic-data/scratch` (or change `EXTRACT_SCRATCH_HOST_DIR`) before `docker compose up`.** |

## Laptop scanner (vuln)
The copies that lived inside this repo (`scanner-agent/` = 1.0.0, `laptop-scanner/` = 1.2.19) were
older than the deployed standalone `laptop-scanner.zip` (1.5.1). Both have been **synced to the
V45-patched 1.5.1 agent** so `Pack-Laptop-Zip.cmd` ships the fix from now on.
| File | Change |
|---|---|
| `scanner-agent/agent/*`, `laptop-scanner/scanner-agent/agent/*` | v1.5.1 + V45: Greenbone default NVT budgets (320 / 36 000 s), `GVM_MAX_CHECKS` honoured |
| `laptop-scanner/docker-compose.yml` | `configure-openvas` writes env-driven timeouts/retries + `safe_checks`, `expand_vhosts`, `test_empty_vhost`, `report_host_details`; `SCAN_IP_MAX_PARALLELISM` default 8 |
| `laptop-scanner/.env` | `PORT_PROFILE=full`, `UDP_PROFILE=priority`, `GVM_OPTIMIZE_TEST=no`, 8 IP workers, watchdog (`MAX_SCAN_RUNTIME_SEC=5400`, `STALL_SEC=1500`), realistic SLO |

Not changed (see review §6): multi-partition mount, NSRL index, downgrade-backup acquisition.

## V45.3a hotfix (2026-10-04, evening)
`scripts/docker-engine-recovery.ps1` and `scripts/stage-evidence.ps1` contained em dashes inside double-quoted
strings. Windows PowerShell 5.1 reads a BOM-less file as CP-1252, where the em dash's third byte (0x94) decodes to
`”`, which PowerShell accepts as a closing quote -> "The string is missing the terminator" at line 130 / missing `}`
at 88 and 74. Both scripts are now pure ASCII (verified with the PowerShell parser under UTF-8 and CP-1252).
Also fixed: `Invoke-ComposeWithRecovery` parameter `-Args` collided with PowerShell's automatic `$args`, so the
`up` arguments were dropped; renamed to `-ComposeCommand`. The rm-f and engine-restart recovery branches were
exercised against a fake `docker` (up fails -> rm -f -> up ok; rm -f fails -> wsl --shutdown -> engine back -> up ok).

## V45.5 - false "Extraction stalled (no progress) - re-queuing from last checkpoint"
Every stall detector keyed on `jobs.updated_at`: frontend auto-resume (240 s), API `/resume` (240 s), pipeline
supervisor (`PIPELINE_STALE_SEC`=55 s). Extraction only wrote that column from inside a few wrapped steps, so a
healthy worker waiting for the CPU lane, opening the E01, enumerating or planning was declared dead and re-queued.
| File | Change |
|---|---|
| `backend/app/services/job_liveness.py` | NEW - task-level liveness thread: bumps `updated_at` every 20 s, refreshes the job lock, logs the current step every 90 s, step timings; `mark_step(job_id, ...)` registry |
| `backend/app/services/inventory_liveness.py` | now a thin subclass (also bumps `updated_at`) |
| `backend/app/services/disk.py` | whole build wrapped in liveness: waiting for CPU lane -> open virtual disk -> extract -> summary |
| `backend/app/services/extracted_disk.py` | step markers: enumerate filesystem, filter + save plan, plan I/O, extract shards, finalize manifest |
| `backend/app/services/job_locks.py` | `cpu_heavy_lease_for_job()` - the worker's own lease heartbeat as the authoritative liveness |
| `backend/app/services/job_control.py` | `extraction_is_stale()` consults the lease before declaring stale; `extract_worker_liveness()` |
| `backend/app/services/pipeline_supervisor.py` | `heartbeat_stale` cleared when the lease is fresh |
| `backend/app/routers/jobs.py` | job rows carry `worker_liveness`; `/resume` on a live job refreshes `updated_at` and explains instead of re-queueing |
| `frontend/src/...` | auto-resume and the stale banner skip jobs whose `worker_liveness.alive` is true (tsc clean) |

## V45.3b - NativeCommandError on "Container ... Running" (Windows PowerShell 5.1)
`start-stack.ps1` runs with `$ErrorActionPreference = "Stop"`. Under Windows PowerShell 5.1, redirecting a native
command's stderr (`2>&1`) converts every stderr line into a terminating NativeCommandError, and Docker Compose
prints its progress on stderr - so the V45.3 recovery wrapper threw on the first healthy line. (PowerShell 7
dropped that behaviour, which is why it passed in testing.)
| File | Change |
|---|---|
| `scripts/docker-engine-recovery.ps1` | every native call goes through `Invoke-NativeCapture` (lowers the preference to Continue for the call, converts ErrorRecords to text, returns exit code); verified under `EAP=Stop` with stderr-only Compose output, both recovery branches |
| `scripts/start-stack.ps1` | the two pre-existing `docker logs ... 2>&1` dumps in error paths use the helper too |
| `scripts/stage-evidence.ps1` | shell script is written to a temp file and bind-mounted instead of passed as a quoted argument (5.1 mangles embedded quotes); `.evidence-staging` marker so `/host/z` is never an empty stub |
| `diagnostics/lint_ps1_native_stderr.py` | NEW - fails on `2>&1` under Stop without a preference guard, and on non-ASCII in code lines; run on any .ps1 change |

## V45.4a - laptop still running the pre-V45 agent (same 3-info / plugin_errors=1 / ~380 s signature)
The log carried no `coverage_retry` event and no `coverage=` field on `completed`, so the container was
executing the old code. Three layers so this can neither hide nor recur:
| File | Change |
|---|---|
| `laptop-scanner/scanner-agent/agent/__init__.py` | `AGENT_BUILD = "1.5.1-v45.4"` |
| `laptop-scanner/scanner-agent/agent/main.py` | startup banner `AGENT BUILD ... plugins_timeout=320s scanner_plugins_timeout=36000s coverage_guard=on`; heartbeat version `1.5.1+v45.4`; **refuses to claim jobs** (logs `DEGRADED SCAN CONFIG` every 60 s) when `scanner_plugins_timeout < 1800` or `plugins_timeout < 120` unless `ALLOW_DEGRADED_SCAN=true`; every `completed` event carries `agent_build` |
| `laptop-scanner/Deploy-V45-Laptop.cmd` | NEW - aborts if run from a stale folder/.env, recreates configure-openvas/openvasd/openvas/ospd-openvas/scanner-agent, prints openvas.conf + the banner |
| `laptop-scanner/Verify-V45-Deployed.cmd` | checks the build stamp inside the running container |
| `backend/app/services/scanner_agent_jobs.py` | central guard: an upload with no coverage data but scanner errors and <= 3 all-info results per host is marked **incomplete** per IP (`degraded_legacy_signature`) - a legacy agent can never produce a green row again |
| `laptop-scanner/.env` | `ALLOW_DEGRADED_SCAN=false` documented |
