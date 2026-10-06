"""Celery apps scoped to one Aetheris product."""

from __future__ import annotations

import os
import tempfile

from celery import Celery

from app.config import get_settings
from app.service_identity import (
    FORENSIC,
    MOBILE_ANDROID,
    MOBILE_EXTRACT,
    MOBILE_IOS,
    MOBILE_SERVICES,
    VULN,
    current_service,
)

FORENSIC_ROUTES = {
    "app.tasks.progress_agent_task": {"queue": "disk-progress"},
    "app.tasks.forensic_serial_stage_task": {"queue": "disk-parse"},
    "app.tasks.build_extracted_disk_task": {"queue": "disk-build"},
    "app.tasks.rag_index_task": {"queue": "rag-index"},
    "app.tasks.phase3_pipeline_task": {"queue": "disk-parse"},
    "app.tasks.phase3_shard_task": {"queue": "disk-parse"},
    "app.tasks.phase3_finalize_task": {"queue": "disk-parse"},
    "app.tasks.parse_drain_task": {"queue": "disk-parse"},
    "app.tasks.parse_shard_task": {"queue": "disk-parse"},
    "app.tasks.parse_bucket_task": {"queue": "disk-parse"},
    "app.tasks.rag_append_task": {"queue": "rag-index"},
    "app.tasks.ocr_drain_task": {"queue": "ocr"},
    "app.tasks.ocr_bucket_task": {"queue": "ocr"},
    # V45.2: own lane — inventory no longer waits behind parse/enrich on disk-parse.
    "app.tasks.axiom_artifact_inventory_task": {"queue": "disk-inventory"},
    "app.tasks.graph_sync_task": {"queue": "agent-orchestration"},
    "app.tasks.rag_enrich_task": {"queue": "disk-parse"},
    "app.tasks.report_gen_task": {"queue": "report-gen"},
    "app.tasks.forensic_agent_chat_task": {"queue": "agent-orchestration"},
    "app.tasks.pipeline_supervisor_task": {"queue": "disk-progress"},
}

def _mobile_routes(prefix: str) -> dict[str, dict[str, str]]:
    build = f"{prefix}-build"
    parse = f"{prefix}-parse"
    rag = f"{prefix}-rag"
    ocr = f"{prefix}-ocr"
    report = f"{prefix}-report"
    return {
        "app.tasks.progress_agent_task": {"queue": f"{prefix}-progress"},
        "app.tasks.forensic_serial_stage_task": {"queue": parse},
        "app.tasks.build_extracted_mobile_task": {"queue": build},
        "app.tasks.parse_drain_mobile_task": {"queue": parse},
        "app.tasks.parse_drain_task": {"queue": parse},
        "app.tasks.parse_shard_task": {"queue": parse},
        "app.tasks.parse_bucket_task": {"queue": parse},
        "app.tasks.axiom_artifact_inventory_mobile_task": {"queue": parse},
        "app.tasks.mobile_analysis_task": {"queue": parse},
        "app.tasks.phase3_pipeline_task": {"queue": parse},
        "app.tasks.phase3_finalize_task": {"queue": parse},
        "app.tasks.phase3_shard_task": {"queue": parse},
        "app.tasks.rag_index_task": {"queue": rag},
        "app.tasks.rag_append_task": {"queue": rag},
        "app.tasks.ocr_drain_task": {"queue": ocr},
        "app.tasks.ocr_bucket_task": {"queue": ocr},
        "app.tasks.graph_sync_task": {"queue": parse},
        "app.tasks.rag_enrich_task": {"queue": parse},
        "app.tasks.pipeline_supervisor_task": {"queue": f"{prefix}-progress"},
        "app.tasks.report_gen_task": {"queue": report},
    }


# Legacy mobile-extract queue names are retained so upgrades can drain old
# jobs without sharing queues with the new Android/iOS products.
MOBILE_ROUTES = {
    "app.tasks.progress_agent_task": {"queue": "mobile-progress"},
    "app.tasks.forensic_serial_stage_task": {"queue": "mobile-build"},
    "app.tasks.build_extracted_mobile_task": {"queue": "mobile-build"},
    "app.tasks.parse_drain_mobile_task": {"queue": "mobile-build"},
    "app.tasks.parse_drain_task": {"queue": "mobile-build"},
    "app.tasks.parse_shard_task": {"queue": "mobile-build"},
    "app.tasks.parse_bucket_task": {"queue": "mobile-build"},
    "app.tasks.axiom_artifact_inventory_mobile_task": {"queue": "mobile-build"},
    "app.tasks.mobile_analysis_task": {"queue": "mobile-build"},
    "app.tasks.phase3_pipeline_task": {"queue": "mobile-build"},
    "app.tasks.phase3_finalize_task": {"queue": "mobile-build"},
    "app.tasks.phase3_shard_task": {"queue": "mobile-build"},
    "app.tasks.rag_index_task": {"queue": "rag-index"},
    "app.tasks.rag_append_task": {"queue": "rag-index"},
    "app.tasks.ocr_drain_task": {"queue": "ocr"},
    "app.tasks.ocr_bucket_task": {"queue": "ocr"},
    "app.tasks.graph_sync_task": {"queue": "mobile-build"},
    "app.tasks.rag_enrich_task": {"queue": "mobile-build"},
    "app.tasks.pipeline_supervisor_task": {"queue": "mobile-progress"},
    "app.tasks.report_gen_task": {"queue": "mobile-build"},
}
ANDROID_ROUTES = _mobile_routes("android")
IOS_ROUTES = _mobile_routes("ios")

VULN_ROUTES = {
    "app.tasks.nessus_scan_sync_task": {"queue": "nessus-sync"},
    "app.tasks.vuln_brd_maintenance_task": {"queue": "nessus-sync"},
    "app.tasks.pentest_job_task": {"queue": "nessus-sync"},
}

_COMMON = {
    "task_serializer": "json",
    "result_serializer": "json",
    "accept_content": ["json"],
    "task_track_started": True,
    "task_acks_late": True,
    # V45.3: never leave a long task un-acked forever on broker loss; it is redelivered.
    "worker_cancel_long_running_tasks_on_connection_loss": True,
    "worker_prefetch_multiplier": 1,
    "broker_connection_retry_on_startup": True,
    "broker_connection_retry": True,
    "broker_connection_max_retries": 100,
    "broker_transport_options": {"visibility_timeout": 3600 * 24 * 14},
    "task_default_queue": "default",
}


def _probe_perf() -> None:
    try:
        from app.services.host_capacity import apply_dynamic_performance
        from app.services.perf_broadcast import publish_live_plan
        from app.services.perf_policy import build_live_plan

        apply_dynamic_performance()
        publish_live_plan(build_live_plan())
    except Exception:
        pass


def create_celery(service: str | None = None) -> Celery:
    svc = service or current_service()
    _probe_perf()
    settings = get_settings()
    celery = Celery(f"aetheris-{svc}", broker=settings.redis_url, backend=settings.redis_url)
    routes = {
        FORENSIC: FORENSIC_ROUTES,
        MOBILE_ANDROID: ANDROID_ROUTES,
        MOBILE_IOS: IOS_ROUTES,
        MOBILE_EXTRACT: MOBILE_ROUTES,
        VULN: VULN_ROUTES,
    }.get(svc, FORENSIC_ROUTES)
    celery.conf.update({**_COMMON, "task_routes": routes})
    # gdbm cannot lock celerybeat-schedule on a Windows Docker bind-mount (/app).
    # Keep the file on the container tmpfs so Beat survives worker restarts.
    celery.conf.beat_schedule_filename = os.path.join(
        tempfile.gettempdir(), f"celerybeat-schedule-{svc}"
    )
    if svc == FORENSIC or svc in MOBILE_SERVICES:
        celery.conf.beat_schedule = {
            "progressAgent": {
                "task": "app.tasks.progress_agent_task",
                "schedule": max(5,min(float(os.environ.get('PROGRESS_AGENT_INTERVAL_SECONDS','15')),30)),
                "kwargs": {},
            },
        }
    register_shutdown_hooks(celery)
    return celery


# ---------------------------------------------------------------------------
# V45.3 — deterministic shutdown. On SIGTERM/SIGQUIT (compose stop/recreate) the
# worker releases what makes a container unkillable or leaves peers waiting:
#   * CUDA residents (GLM-OCR, embedder) so the nvidia context is torn down before
#     the process exits (Docker Desktop/WSL2 cannot kill a container that still
#     holds a GPU context);
#   * Redis heavy leases / job locks held by this process so other products do not
#     wait on a stale GPU lane for the lock TTL.
# ---------------------------------------------------------------------------

def _release_on_shutdown(**_kwargs) -> None:
    import logging
    import os

    log = logging.getLogger("celery.shutdown")
    if (os.environ.get("CELERY_SHUTDOWN_RELEASE_GPU") or "true").strip().lower() not in {"1", "true", "yes", "on"}:
        return
    for label, fn in (
        ("glm-ocr", lambda: __import__("app.services.ocr_gpu", fromlist=["unload_glm_ocr"]).unload_glm_ocr()),
        ("embedder", lambda: __import__("app.services.embedding_gpu", fromlist=["unload_embedder"]).unload_embedder()),
        ("gpu-lease", lambda: __import__("app.services.job_locks", fromlist=["release_gpu_heavy_slot"]).release_gpu_heavy_slot()),
        ("cpu-lease", lambda: __import__("app.services.job_locks", fromlist=["release_cpu_heavy_slot"]).release_cpu_heavy_slot()),
    ):
        try:
            fn()
            log.info("shutdown: released %s", label)
        except Exception as exc:  # never block shutdown
            log.debug("shutdown: %s release skipped: %s", label, exc)
    try:
        import torch

        if torch.cuda.is_available():
            torch.cuda.synchronize()
            torch.cuda.empty_cache()
    except Exception:
        pass


def register_shutdown_hooks(app) -> None:
    try:
        from celery.signals import worker_process_shutdown, worker_shutting_down

        worker_shutting_down.connect(_release_on_shutdown, weak=False)
        worker_process_shutdown.connect(_release_on_shutdown, weak=False)
    except Exception:
        pass
