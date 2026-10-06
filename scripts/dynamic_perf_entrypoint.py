#!/usr/bin/env python3
"""Apply dynamic host-capacity knobs, then exec the real process.

Usage (compose):
  entrypoint: ["python", "/scripts/dynamic_perf_entrypoint.py"]
  command: ["celery", "-A", "app.celery_app.celery", "worker", ...]
"""

from __future__ import annotations

import os
import sys


def _rewrite_celery_concurrency(argv: list[str]) -> list[str]:
    """Inject/replace --concurrency for light and forensic queues from env."""
    if not argv or argv[0] != "celery" or "worker" not in argv:
        return argv
    queues = ""
    for i, part in enumerate(argv):
        if part in ("-Q", "--queues") and i + 1 < len(argv):
            queues = argv[i + 1]
            break
        if part.startswith("--queues="):
            queues = part.split("=", 1)[1]
    queue_set = {q.strip() for q in queues.split(",") if q.strip()}

    forensic = {"disk-build", "report-gen"}
    conc = ""
    if queue_set == {"ocr"}:
        # Never inherit OCR_CPU_WORKERS (8). Prefork + CUDA after thermal prep
        # makes torch.cuda.is_available() false in children and OCR freezes ~25%.
        conc = "1"
    elif queue_set == {"mobile-build"}:
        raw = (
            os.environ.get("MOBILE_WORKER_CONCURRENCY", "").strip()
            or os.environ.get("EXTRACT_MOBILE_WORKERS", "").strip()
            or os.environ.get("FORENSIC_WORKER_CONCURRENCY", "").strip()
        )
        if raw.isdigit():
            conc = str(max(1, min(8, int(raw))))
    elif queue_set and queue_set.issubset(forensic):
        raw = (
            os.environ.get("FORENSIC_WORKER_CONCURRENCY", "").strip()
            or os.environ.get("MAX_CONCURRENT_DISK_BUILDS", "").strip()
        )
        if raw.isdigit():
            conc = str(max(1, min(8, int(raw))))
    else:
        # Disk/mobile/rag are not in this set; do not rewrite GPU workers.
        light = {"agent-orchestration", "nessus-sync", "default"}
        if queue_set and not queue_set.issubset(light):
            return argv
        if queue_set == {"nessus-sync"}:
            conc = (
                os.environ.get("NESSUS_WORKER_CONCURRENCY", "").strip()
                or os.environ.get("VULN_MAX_PARALLEL_JOBS", "").strip()
                or os.environ.get("CELERY_LIGHT_CONCURRENCY", "").strip()
            )
            if conc.isdigit():
                conc = str(max(1, min(8, int(conc))))
        else:
            conc = os.environ.get("CELERY_LIGHT_CONCURRENCY", "").strip()

    if not conc.isdigit():
        return argv
    out: list[str] = []
    skip_next = False
    replaced = False
    for i, part in enumerate(argv):
        if skip_next:
            skip_next = False
            continue
        if part in ("-c", "--concurrency"):
            out.extend([part, conc])
            skip_next = True
            replaced = True
            continue
        if part.startswith("--concurrency="):
            out.append(f"--concurrency={conc}")
            replaced = True
            continue
        out.append(part)
    if not replaced:
        # Insert after 'worker'
        try:
            wi = out.index("worker")
            out[wi + 1 : wi + 1] = ["--concurrency", conc]
        except ValueError:
            out.extend(["--concurrency", conc])
    return out


def _rewrite_ocr_solo_pool(argv: list[str]) -> list[str]:
    """OCR drain must be solo so GLM-OCR sees the same CUDA context as nvidia-smi."""
    if not argv or argv[0] != "celery" or "worker" not in argv:
        return argv
    queues = ""
    for i, part in enumerate(argv):
        if part in ("-Q", "--queues") and i + 1 < len(argv):
            queues = argv[i + 1]
            break
        if part.startswith("--queues="):
            queues = part.split("=", 1)[1]
    queue_set = {q.strip() for q in queues.split(",") if q.strip()}
    if queue_set != {"ocr"}:
        return argv
    out: list[str] = []
    skip_next = False
    has_pool = False
    for i, part in enumerate(argv):
        if skip_next:
            skip_next = False
            continue
        if part in ("-P", "--pool"):
            out.extend([part, "solo"])
            skip_next = True
            has_pool = True
            continue
        if part.startswith("--pool="):
            out.append("--pool=solo")
            has_pool = True
            continue
        out.append(part)
    if not has_pool:
        try:
            wi = out.index("worker")
            out[wi + 1 : wi + 1] = ["--pool", "solo"]
        except ValueError:
            out.extend(["--pool", "solo"])
    return out


def _rewrite_beat_schedule(argv: list[str]) -> list[str]:
    """Keep celerybeat-schedule off Windows bind-mounts when a worker embeds Beat."""
    if not argv or argv[0] != "celery":
        return argv
    if "-B" not in argv and "--beat" not in argv and "beat" not in argv:
        return argv
    if any(part == "-s" or part == "--schedule" or part.startswith("--schedule=") for part in argv):
        return argv
    schedule = os.path.join(
        os.environ.get("TMPDIR") or os.environ.get("TEMP") or "/tmp",
        "celerybeat-schedule",
    )
    out = list(argv)
    if "beat" in out:
        idx = out.index("beat")
        out[idx + 1 : idx + 1] = ["--schedule", schedule]
        return out
    out.extend(["--schedule", schedule])
    return out


def main() -> None:
    # Keep tempfile/scratch on the host backup mount, not the container layer.
    tmp = os.environ.get("TMPDIR") or os.environ.get("TMP")
    if tmp:
        os.makedirs(tmp, exist_ok=True)

    # Ensure backend is importable when cwd varies
    app_root = os.environ.get("PYTHONPATH", "/app")
    if app_root and app_root not in sys.path:
        sys.path.insert(0, app_root)

    try:
        from app.services.host_capacity import apply_dynamic_performance

        apply_dynamic_performance()
    except Exception as exc:  # never block startup
        print(f"[dynamic_perf] apply failed (continuing): {exc}", file=sys.stderr)

    # Cap GPU power immediately on GPU workers — prevents thermal runaway before first batch.
    try:
        queues = " ".join(sys.argv[1:])
        if "rag-index" in queues or "ocr" in queues:
            from app.services.gpu_thermal import prepare_gpu_for_heavy_work

            # Power-cap only. Never block Celery startup on an unreachable resume temp
            # (laptop idle GPU often sits at 70–77°C; waiting for 62°C stalls OCR forever).
            prep = prepare_gpu_for_heavy_work(
                reason="worker_start", unload_ollama=False, wait_for_cool=False
            )
            print(
                f"[dynamic_perf] GPU thermal prep power_limit={prep.get('power_limit_w')}W "
                f"pause={prep.get('pause_c')}°C abort={prep.get('abort_c')}°C",
                file=sys.stderr,
            )
    except Exception as exc:
        print(f"[dynamic_perf] GPU thermal prep skipped: {exc}", file=sys.stderr)

    if len(sys.argv) < 2:
        print("usage: dynamic_perf_entrypoint.py <command> [args...]", file=sys.stderr)
        sys.exit(2)

    cmd = _rewrite_beat_schedule(_rewrite_ocr_solo_pool(_rewrite_celery_concurrency(sys.argv[1:])))
    os.execvp(cmd[0], cmd)


if __name__ == "__main__":
    main()
