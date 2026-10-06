"""Dynamic host-capacity performance planner.

Probes CPU / RAM / GPU room on the machine (laptop or desktop) and sets
extract / parse / RAG / thermal knobs so throughput scales up when there is
headroom and backs off when memory, load, or temperature is tight.
"""

from __future__ import annotations

import logging
import os
import re
import shutil
import subprocess
import threading
from dataclasses import asdict, dataclass, field
from typing import Any

log = logging.getLogger("host_capacity")

_apply_lock = threading.Lock()
_last_plan: "CapacityPlan | None" = None


@dataclass
class HostSnapshot:
    cpu_logical: int = 1
    mem_total_mb: int = 0
    mem_available_mb: int = 0
    load_1m: float | None = None
    cpu_temp_c: int | None = None
    gpu_available: bool = False
    gpu_name: str | None = None
    gpu_vram_total_mb: int | None = None
    gpu_vram_free_mb: int | None = None
    gpu_temp_c: int | None = None
    npu_available: bool = False
    npu_name: str | None = None
    profile: str = "unknown"  # tight | laptop | desktop | workstation


@dataclass
class CapacityPlan:
    profile: str
    snapshot: HostSnapshot
    env: dict[str, str] = field(default_factory=dict)
    notes: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return {
            "profile": self.profile,
            "snapshot": asdict(self.snapshot),
            "env": dict(self.env),
            "notes": list(self.notes),
        }


def _read_meminfo_mb() -> tuple[int, int]:
    total = avail = 0
    try:
        with open("/proc/meminfo", encoding="utf-8") as fh:
            for line in fh:
                if line.startswith("MemTotal:"):
                    total = int(line.split()[1]) // 1024
                elif line.startswith("MemAvailable:"):
                    avail = int(line.split()[1]) // 1024
    except Exception:
        pass
    if total <= 0:
        # Fallback for non-Linux / restricted containers
        try:
            import ctypes

            class MEMORYSTATUSEX(ctypes.Structure):
                _fields_ = [
                    ("dwLength", ctypes.c_ulong),
                    ("dwMemoryLoad", ctypes.c_ulong),
                    ("ullTotalPhys", ctypes.c_ulonglong),
                    ("ullAvailPhys", ctypes.c_ulonglong),
                    ("ullTotalPageFile", ctypes.c_ulonglong),
                    ("ullAvailPageFile", ctypes.c_ulonglong),
                    ("ullTotalVirtual", ctypes.c_ulonglong),
                    ("ullAvailVirtual", ctypes.c_ulonglong),
                    ("ullAvailExtendedVirtual", ctypes.c_ulonglong),
                ]

            stat = MEMORYSTATUSEX()
            stat.dwLength = ctypes.sizeof(MEMORYSTATUSEX)
            if ctypes.windll.kernel32.GlobalMemoryStatusEx(ctypes.byref(stat)):
                total = int(stat.ullTotalPhys // (1024 * 1024))
                avail = int(stat.ullAvailPhys // (1024 * 1024))
        except Exception:
            total = total or 8192
            avail = avail or 4096
    return max(total, 1), max(avail, 0)


def _read_load_1m() -> float | None:
    try:
        return float(os.getloadavg()[0])
    except (AttributeError, OSError):
        return None


def _read_cpu_temp_c() -> int | None:
    """Best-effort CPU package temperature (Linux thermal zones / hwmon)."""
    bases = [
        "/sys/class/thermal",
        "/sys/class/hwmon",
    ]
    temps: list[int] = []
    for base in bases:
        if not os.path.isdir(base):
            continue
        try:
            for name in os.listdir(base):
                path = os.path.join(base, name)
                # thermal_zone*/temp (millidegree)
                tpath = os.path.join(path, "temp")
                if os.path.isfile(tpath):
                    try:
                        raw = int(open(tpath, encoding="utf-8").read().strip())
                        c = raw // 1000 if raw > 200 else raw
                        if 20 <= c <= 110:
                            temps.append(c)
                    except Exception:
                        pass
                # hwmon*/temp*_input
                for fname in os.listdir(path) if os.path.isdir(path) else []:
                    if not re.match(r"temp\d+_input$", fname):
                        continue
                    try:
                        raw = int(open(os.path.join(path, fname), encoding="utf-8").read().strip())
                        c = raw // 1000 if raw > 200 else raw
                        if 20 <= c <= 110:
                            temps.append(c)
                    except Exception:
                        pass
        except Exception:
            continue
    if not temps:
        return None
    return max(temps)


def _probe_gpu() -> tuple[bool, str | None, int | None, int | None, int | None]:
    """Return (available, name, vram_total_mb, vram_free_mb, temp_c)."""
    # Prefer existing thermal helper when importable (workers).
    try:
        from app.services.gpu_thermal import get_gpu_stats

        stats = get_gpu_stats()
        if stats.available:
            free = None
            if stats.memory_total_mb is not None and stats.memory_used_mb is not None:
                free = max(int(stats.memory_total_mb) - int(stats.memory_used_mb), 0)
            return True, stats.name, stats.memory_total_mb, free, stats.temperature_c
    except Exception:
        pass

    if not shutil.which("nvidia-smi"):
        # torch may still see CUDA inside the image
        try:
            import torch

            if torch.cuda.is_available():
                props = torch.cuda.get_device_properties(0)
                total = int(props.total_memory // (1024 * 1024))
                free = None
                try:
                    free_b, _ = torch.cuda.mem_get_info(0)
                    free = int(free_b // (1024 * 1024))
                except Exception:
                    free = total
                return True, props.name, total, free, None
        except Exception:
            pass
        return False, None, None, None, None

    try:
        out = subprocess.check_output(
            [
                "nvidia-smi",
                "--query-gpu=name,memory.total,memory.free,temperature.gpu",
                "--format=csv,noheader,nounits",
            ],
            stderr=subprocess.DEVNULL,
            text=True,
            timeout=5,
        ).strip()
        if not out:
            return False, None, None, None, None
        line = out.splitlines()[0]
        parts = [p.strip() for p in line.split(",")]
        name = parts[0] if parts else None
        total = int(float(parts[1])) if len(parts) > 1 and parts[1] else None
        free = int(float(parts[2])) if len(parts) > 2 and parts[2] else None
        temp = int(float(parts[3])) if len(parts) > 3 and parts[3] else None
        return True, name, total, free, temp
    except Exception:
        return False, None, None, None, None


def _probe_npu() -> tuple[bool, str | None]:
    """Detect Intel/Qualcomm NPU or Linux accel devices. Env can force on/off."""
    forced = (os.environ.get("AETHERIS_NPU") or os.environ.get("NPU_AVAILABLE") or "").strip().lower()
    if forced in {"1", "true", "yes", "on"}:
        return True, (os.environ.get("AETHERIS_NPU_NAME") or "npu").strip() or "npu"
    if forced in {"0", "false", "no", "off"}:
        return False, None
    for path in ("/dev/accel/accel0", "/sys/class/accel"):
        if os.path.exists(path):
            return True, "linux-accel"
    try:
        drm = "/sys/class/drm"
        if os.path.isdir(drm):
            for name in os.listdir(drm):
                if "npu" in name.lower():
                    return True, name
    except Exception:
        pass
    ps = shutil.which("powershell.exe") or shutil.which("pwsh")
    if ps:
        try:
            out = subprocess.check_output(
                [
                    ps,
                    "-NoProfile",
                    "-Command",
                    "(Get-PnpDevice -Status OK -ErrorAction SilentlyContinue |"
                    " Where-Object { $_.FriendlyName -match 'NPU|AI Boost|Hexagon' } |"
                    " Select-Object -First 1 -ExpandProperty FriendlyName)",
                ],
                stderr=subprocess.DEVNULL,
                text=True,
                timeout=4,
            ).strip()
            if out:
                return True, out.splitlines()[0].strip()
        except Exception:
            pass
    return False, None


def probe_host() -> HostSnapshot:
    cpus = max(int(os.cpu_count() or 1), 1)
    mem_total, mem_avail = _read_meminfo_mb()
    load = _read_load_1m()
    cpu_temp = _read_cpu_temp_c()
    gpu_ok, gpu_name, vram_total, vram_free, gpu_temp = _probe_gpu()
    npu_ok, npu_name = _probe_npu()

    # Classify machine class from visible resources (container cgroup-aware via /proc).
    laptopish_name = bool(gpu_name and re.search(r"laptop|mobile|max-q|geforce\s*rtx\s*\d{4}\s*laptop", gpu_name, re.I))
    if mem_total < 10_000 or cpus <= 4 or (vram_total is not None and vram_total < 6000):
        profile = "tight"
    elif mem_total < 20_000 or cpus <= 10 or laptopish_name or (vram_total is not None and vram_total <= 12288):
        profile = "laptop"
    elif mem_total < 48_000:
        profile = "desktop"
    else:
        profile = "workstation"

    # Tighten if currently under pressure
    if mem_avail and mem_avail < 2048:
        profile = "tight"
    if cpu_temp is not None and cpu_temp >= 90:
        profile = "tight"
    if gpu_temp is not None and gpu_temp >= 85:
        if profile == "workstation":
            profile = "desktop"
        elif profile == "desktop":
            profile = "laptop"

    return HostSnapshot(
        cpu_logical=cpus,
        mem_total_mb=mem_total,
        mem_available_mb=mem_avail,
        load_1m=load,
        cpu_temp_c=cpu_temp,
        gpu_available=gpu_ok,
        gpu_name=gpu_name,
        gpu_vram_total_mb=vram_total,
        gpu_vram_free_mb=vram_free,
        gpu_temp_c=gpu_temp,
        npu_available=npu_ok,
        npu_name=npu_name,
        profile=profile,
    )


def _clamp(n: int, lo: int, hi: int) -> int:
    return max(lo, min(hi, n))


def _gpu_memory_fraction(vram_mb: int) -> float:
    """Use most of the card, but leave ~20–25% for other apps / desktop / Ollama."""
    if vram_mb >= 22000:
        return 0.80
    if vram_mb >= 15000:
        return 0.78
    if vram_mb >= 11000:
        return 0.75
    if vram_mb >= 8000:
        return 0.70
    if vram_mb >= 4000:
        return 0.58
    return 0.42


def build_capacity_plan(snap: HostSnapshot | None = None) -> CapacityPlan:
    snap = snap or probe_host()
    notes: list[str] = []
    env: dict[str, str] = {}

    cpus_all = snap.cpu_logical
    # Leave cores for desktop / other apps so extraction does not pin the host.
    reserved_cpus = min(2, max(1, cpus_all // 8))
    cpus = max(1, cpus_all - reserved_cpus)
    avail = snap.mem_available_mb or (snap.mem_total_mb // 2)
    vram = snap.gpu_vram_total_mb or 0
    profile = snap.profile

    # Leave ~30% RAM for OS / Postgres / Ollama / browser / other apps.
    usable_mb = int(avail * 0.70)
    notes.append(
        f"profile={profile} cpus={cpus}/{cpus_all} reserved={reserved_cpus} "
        f"mem_avail={avail}MB gpu={snap.gpu_name or 'none'} vram={vram}MB "
        f"npu={snap.npu_name or 'none'}"
    )

    # Thermal ceilings are intentionally below typical OEM shutdown (~85–95°C).
    if profile == "tight":
        extract_readers = 1
        shards = 4
        upload = 2
        parse_workers = 2
        parse_buckets = 1
        parse_batch = 2000
        parse_drain = 100
        rag_batch = 4
        rag_cap = 6
        ocr_batch = 12
        ocr_cpu = 2
        cuda_frac = 0.28
        max_disk = 2
        mobile_conc = 1
        vuln_conc = 2
        ollama_parallel = 1
        celery_light = 1
        power_w = 60
        pause_c, throttle_c, start_max, abort_c = 72, 66, 56, 76
        duty_batches, duty_rest, embed_rest = 2, 6.0, 1.5
        stream_rag = False
    elif profile == "laptop":
        # Laptop GPUs hard-trip near 85°C; dual OCR+RAG+finalize caused shutdowns.
        extract_readers = 3
        shards = _clamp(cpus // 2, 4, 8)
        upload = _clamp(cpus // 4, 2, 4)
        parse_workers = _clamp(cpus // 2, 6, 12)
        parse_buckets = 4
        parse_batch = 6000 if usable_mb > 6000 else 4000
        parse_drain = 300
        rag_batch = 8 if vram >= 8000 else 4
        rag_cap = 16 if vram >= 10000 else 10
        ocr_batch = 24
        ocr_cpu = _clamp(max(4, cpus // 3), 4, 6)
        cuda_frac = 0.32 if vram >= 10000 else 0.28
        max_disk = 3 if usable_mb > 8000 else 2
        mobile_conc = 2 if usable_mb > 6000 else 1
        vuln_conc = 3 if usable_mb > 8000 else 2
        ollama_parallel = 1
        celery_light = 1
        power_w = 70
        pause_c, throttle_c, start_max, abort_c = 92, 87, 90, 94
        duty_batches, duty_rest, embed_rest = 4, 3.0, 0.6
        stream_rag = False
        # 12GB laptop (RTX 5070 Ti): exclusive OCR XOR RAG can use more of the card.
        if vram >= 11000:
            extract_readers = 8
            shards = _clamp(cpus // 2, 10, 14)
            upload = _clamp(cpus // 3, 6, 10)
            parse_workers = _clamp(cpus // 2, 10, 16)
            rag_batch = 24
            rag_cap = 48
            ocr_batch = 32
            ocr_cpu = _clamp(cpus // 2, 6, 8)
            cuda_frac = 0.42
            max_disk = max(max_disk, 4)
            mobile_conc = max(mobile_conc, 3)
            duty_batches, duty_rest, embed_rest = 8, 1.5, 0.20
            notes.append(
                "laptop 12GB — 8 EWF readers + larger parse/inventory; OCR + RAG GPU slots"
            )
        notes.append(
            "laptop thermal profile — cool@70W / hot→50W adaptive; pause 92°C / abort 94°C (below OEM ~95–100°C)"
        )
    elif profile == "desktop":
        extract_readers = 4
        shards = _clamp(cpus // 2, 6, 10)
        upload = _clamp(cpus // 3, 3, 6)
        parse_workers = _clamp(cpus // 2, 6, 12)
        parse_buckets = 4
        parse_batch = 8000 if usable_mb > 10000 else 6000
        parse_drain = 400
        rag_batch = 12 if vram >= 16000 else 8
        rag_cap = 16 if vram >= 16000 else 12
        ocr_batch = 30
        ocr_cpu = _clamp(cpus // 3, 6, 8)
        cuda_frac = 0.42 if vram >= 16000 else 0.36
        max_disk = 4 if usable_mb > 16000 else 3
        mobile_conc = 3
        vuln_conc = 4
        ollama_parallel = 1
        celery_light = 2
        power_w = 100
        pause_c, throttle_c, start_max, abort_c = 90, 85, 85, 90
        duty_batches, duty_rest, embed_rest = 4, 4.0, 0.8
        stream_rag = False
        notes.append("desktop thermal profile — GPU pause 90°C / abort 90°C / power ≤100W")
    else:  # workstation
        extract_readers = _clamp(cpus // 4, 2, 4)
        shards = _clamp(cpus, 8, 14)
        upload = _clamp(cpus // 2, 4, 8)
        parse_workers = _clamp(cpus // 2, 8, 16)
        parse_buckets = 4
        parse_batch = 10000
        parse_drain = 600
        rag_batch = 16 if vram >= 20000 else 12
        rag_cap = 24 if vram >= 20000 else 16
        ocr_batch = 40
        ocr_cpu = _clamp(cpus // 3, 6, 10)
        cuda_frac = 0.50 if vram >= 20000 else 0.42
        max_disk = _clamp(usable_mb // 6000, 3, 6)
        mobile_conc = _clamp(cpus // 4, 2, 4)
        vuln_conc = _clamp(cpus // 3, 3, 8)
        ollama_parallel = 2 if vram >= 20000 else 1
        celery_light = 3
        power_w = 140
        pause_c, throttle_c, start_max, abort_c = 80, 74, 65, 84
        duty_batches, duty_rest, embed_rest = 5, 3.0, 0.6
        stream_rag = bool(vram >= 16000 and (snap.gpu_temp_c or 0) < 60)

    if snap.gpu_available and vram > 0:
        hw_frac = _gpu_memory_fraction(int(vram))
        if profile == "laptop" and vram < 11000:
            cuda_frac = min(max(cuda_frac, 0.32), 0.42)
        else:
            cuda_frac = max(cuda_frac, hw_frac)
        if vram >= 22000:
            rag_batch = max(rag_batch, 24)
            rag_cap = max(rag_cap, 40)
            ocr_batch = max(ocr_batch, 48)
        elif vram >= 15000:
            rag_batch = max(rag_batch, 16)
            rag_cap = max(rag_cap, 28)
            ocr_batch = max(ocr_batch, 36)
        elif vram >= 11000:
            rag_batch = max(rag_batch, 12)
            rag_cap = max(rag_cap, 24)
            ocr_batch = max(ocr_batch, 32)
        notes.append(
            f"GPU VRAM {vram}MB — cuda_frac={cuda_frac:.2f} rag_batch={rag_batch} "
            "(headroom reserved for other apps)"
        )

    # Load / thermal overrides — keep machine responsive (never raise ceilings here).
    if snap.load_1m is not None and snap.load_1m > cpus * 0.75:
        parse_workers = max(1, parse_workers // 2)
        upload = max(1, upload // 2)
        parse_buckets = 1
        notes.append("high load — reduced parse/upload concurrency")
    if snap.cpu_temp_c is not None and snap.cpu_temp_c >= 85:
        parse_workers = max(1, parse_workers // 2)
        parse_buckets = 1
        rag_batch = max(2, rag_batch // 2)
        ocr_batch = max(8, ocr_batch // 2)
        ocr_cpu = max(2, ocr_cpu // 2)
        stream_rag = False
        notes.append(f"CPU {snap.cpu_temp_c}°C — thermal backoff")
    if snap.cpu_temp_c is not None and snap.cpu_temp_c >= 92:
        parse_workers = 1
        parse_buckets = 1
        rag_batch = 2
        ocr_batch = 8
        ocr_cpu = 2
        stream_rag = False
        notes.append(f"CPU {snap.cpu_temp_c}°C — near shutdown, minimal parallelism")
    if snap.gpu_temp_c is not None and snap.gpu_temp_c >= 80:
        rag_batch = max(2, rag_batch // 2)
        rag_cap = max(rag_batch, rag_cap // 2)
        ocr_batch = max(8, ocr_batch // 2)
        cuda_frac = min(cuda_frac, 0.28)
        stream_rag = False
        notes.append(f"GPU {snap.gpu_temp_c}°C — smaller embed/OCR batches")
    if snap.gpu_temp_c is not None and snap.gpu_temp_c >= pause_c:
        rag_batch = 2
        ocr_batch = 8
        stream_rag = False
        notes.append(f"GPU {snap.gpu_temp_c}°C >= pause — GPU work should idle")

    if snap.npu_available:
        mobile_conc = min(mobile_conc + 1, 4)
        vuln_conc = min(vuln_conc + 1, 8)
        notes.append(
            f"NPU {snap.npu_name} — extra inference capacity; GPU kept for accuracy models"
        )
        env["NPU_AVAILABLE"] = "true"
        env["NPU_NAME"] = snap.npu_name or "npu"
    else:
        env["NPU_AVAILABLE"] = "false"

    env["OCR_DEVICE"] = "cuda" if snap.gpu_available else "cpu"
    if not snap.gpu_available:
        if snap.npu_available:
            env["RAG_EMBEDDING_DEVICE"] = "npu"
            notes.append("no GPU — NPU embeddings; OCR stays CPU (text-layer only)")
        else:
            env["RAG_EMBEDDING_DEVICE"] = "cpu"
            notes.append("no GPU detected — CPU embeddings; OCR stays CPU (text-layer only)")
        rag_batch = min(rag_batch, 4)
        rag_cap = min(rag_cap, 4)
    else:
        env["RAG_EMBEDDING_DEVICE"] = "cuda"
        notes.append("GPU present — CUDA embeddings; OCR agent uses GLM on CUDA when the slot is free")

    # Independent stacks share one host. Cap combined celery workers to RAM.
    share_host = _truthy(os.environ.get("AETHERIS_SHARE_HOST"), True)
    if share_host:
        budget = max(3, usable_mb // 1500)
        max_disk = min(max_disk, max(2, int(budget * 0.45)))
        mobile_conc = min(mobile_conc, max(3, int(budget * 0.30)))
        vuln_conc = min(vuln_conc, max(2, int(budget * 0.20)))
        notes.append(
            f"shared host budget={budget} forensic={max_disk} mobile={mobile_conc} vuln={vuln_conc}"
        )

    # Physical GPU is shared even though each stack has its own Redis.
    # Split reservation so disk + mobile cannot both take 2 slots (4 CUDA jobs).
    gpu_slots = 2 if vram >= 11000 else 1
    ocr_cuda_frac = 0.45 if vram >= 11000 else 0.55
    if share_host and snap.gpu_available:
        try:
            from app.service_identity import VULN, current_service

            svc = current_service()
        except Exception:
            svc = "forensic"
        if svc == VULN:
            gpu_slots = 0
            notes.append("vuln stack does not reserve GPU — OpenVAS/Nmap stay CPU/network")
        else:
            gpu_slots = 1
            ocr_cuda_frac = 0.32 if vram < 11000 else 0.35
            notes.append(
                f"shared host GPU reservation: {svc} gets 1 exclusive slot "
                "(peer stack gets the other; extract/parse stay off this wait)"
            )

    # Mobile folder extract is I/O-bound. Cool hosts get more readers; ZIP stays safe via planner.
    mobile_readers = 3 if profile in ("tight",) else _clamp(12 if profile == "laptop" else 14, 4, 16)
    if profile == "laptop" and vram >= 11000:
        mobile_readers = _clamp(max(mobile_readers, 12), 8, 16)
    if snap.cpu_temp_c is not None and snap.cpu_temp_c >= 90:
        mobile_readers = max(2, mobile_readers // 2)
    inv_workers = _clamp(min(8, max(2, cpus // 3)), 2, 8)
    if profile == "laptop" and vram >= 11000:
        inv_workers = _clamp(max(inv_workers, 6), 2, 8)
    if snap.cpu_temp_c is not None and snap.cpu_temp_c >= 85:
        inv_workers = max(1, inv_workers // 2)

    from app.services.ollama_model_plan import plan_ollama_models

    ollama_plan = plan_ollama_models(
        vram_mb=int(vram or 0),
        gpu_available=bool(snap.gpu_available),
    )
    notes.extend(ollama_plan.notes)
    env.update(
        {
            "OLLAMA_PULL_MODELS": ollama_plan.csv(),
            "LLM_PRIMARY_MODEL": ollama_plan.primary,
            "LLM_REVIEW_MODEL": ollama_plan.review,
            "LLM_REVIEW_MODEL_LARGE": ollama_plan.review,
            "LLM_FAST_MODEL": ollama_plan.fast,
            "RAG_EMBEDDING_FALLBACK": ollama_plan.embed,
            "AGENT_MODEL": ollama_plan.fast,
            "MOBILE_REPORT_LLM_MODEL": ollama_plan.primary,
        }
    )

    env.update(
        {
            "DYNAMIC_PERF_PROFILE": profile,
            "EXTRACT_DISK_WORKERS": str(extract_readers),
            "EXTRACT_MOBILE_WORKERS": str(mobile_readers),
            "EXTRACT_SHARD_COUNT": str(shards),
            "EXTRACT_UPLOAD_CONCURRENCY": str(upload),
            "MAX_CONCURRENT_DISK_BUILDS": str(max_disk),
            "FORENSIC_WORKER_CONCURRENCY": str(max_disk),
            "MOBILE_WORKER_CONCURRENCY": str(mobile_conc),
            "NESSUS_WORKER_CONCURRENCY": str(vuln_conc),
            "VULN_MAX_PARALLEL_JOBS": str(vuln_conc),
            "PARSE_DRAIN_MAX_ROUNDS": "20",
            "PARSE_DRAIN_INTERLEAVE_RAG": "false",
            "PARSE_PARALLEL_ENABLED": "true",
            # Total parse threads ≈ PARSE_WORKERS across PARSE_PARALLEL_BUCKETS Celery tasks.
            "PARSE_WORKERS": str(parse_workers),
            "PARSE_BATCH_LIMIT": str(parse_batch),
            "PARSE_DRAIN_BATCH_LIMIT": str(parse_drain),
            "PARSE_PARALLEL_BUCKETS": str(parse_buckets),
            "OCR_BATCH_LIMIT": str(ocr_batch),
            "OCR_CPU_WORKERS": str(ocr_cpu),
            "OCR_PARALLEL_BUCKETS": "3",
            "OCR_CELERY_CONCURRENCY": str(max(parse_buckets + 1, 5)),
            # Inventory counting is SQL-bound; keep modest under thermal pressure.
            "AXIOM_INVENTORY_WORKERS": str(inv_workers),
            "AXIOM_INVENTORY_BATCH_SIZE": "200" if vram >= 11000 else "100",
            "CATALOG_INVENTORY_WORKERS": str(inv_workers),
            "CATALOG_INVENTORY_BATCH_SIZE": "200" if vram >= 11000 else "100",
            "RAG_EMBEDDING_ENABLED": "false",
            "RAG_AUTO_AFTER_DISK": "false",
            "RAG_BACKGROUND_AFTER_BASELINE": "false",
            "RAG_BATCH_SIZE": str(rag_batch),
            "RAG_BATCH_SIZE_CAP": str(rag_cap),
            "RAG_CUDA_MEMORY_FRACTION": f"{cuda_frac:.2f}",
            # Evidence extraction is a hard barrier by default. Dynamic tuning
            # must never silently turn Phase 3 streaming back on while an image
            # is still being enumerated/read.
            "EXTRACT_THEN_PROCESS": "true",
            "PHASE3_STREAM_RAG_DURING_EXTRACT": "false",
            "PHASE3_STREAM_OCR_DURING_EXTRACT": "false",
            "PHASE3_STREAM_DURING_EXTRACT": "false",
            "PIPELINE_SEQUENTIAL_AGENTS": "false",
            "OLLAMA_NUM_PARALLEL": str(ollama_parallel),
            "GPU_THERMAL_ENABLED": "true",
            "GPU_THERMAL_PAUSE_C": str(pause_c),
            "GPU_THERMAL_THROTTLE_C": str(throttle_c),
            "GPU_THERMAL_START_MAX_C": str(start_max),
            "GPU_THERMAL_RESUME_C": str(max(pause_c - 12, 50)),
            "GPU_THERMAL_ABORT_C": str(abort_c),
            "GPU_THERMAL_POWER_LIMIT_W": str(power_w),
            "GPU_THERMAL_DUTY_CYCLE_BATCHES": str(duty_batches),
            "GPU_THERMAL_DUTY_CYCLE_REST_SEC": str(duty_rest),
            "GPU_THERMAL_EMBED_REST_SEC": str(embed_rest),
            "GPU_THERMAL_HOT_BATCH_SLEEP_SEC": "6",
            "GPU_THERMAL_RISE_DELTA_C": "5",
            "GPU_THERMAL_RISE_WINDOW_SEC": "15",
            "GPU_THERMAL_ADAPTIVE_BATCH": "true",
            "GPU_THERMAL_FALLBACK_DUTY": "true",
            "CELERY_LIGHT_CONCURRENCY": str(celery_light),
            # Cap BLAS threads per process — buckets already multiply process count.
            "OMP_NUM_THREADS": str(_clamp(max(1, parse_workers // 2), 1, 2)),
            "MKL_NUM_THREADS": str(_clamp(max(1, parse_workers // 2), 1, 2)),
            "TOKENIZERS_PARALLELISM": "false",
            "GPU_HEAVY_MAX_CONCURRENT": str(max(gpu_slots, 1) if snap.gpu_available else 1),
            "OCR_CUDA_MEMORY_FRACTION": f"{ocr_cuda_frac:.2f}",
            "VULN_TARGET_WORKERS": str(max(2, min(8, vuln_conc))),
            "VULN_OPENVAS_IP_WORKERS": str(max(2, min(8, vuln_conc))),
        }
    )

    return CapacityPlan(profile=profile, snapshot=snap, env=env, notes=notes)


def _truthy(val: str | None, default: bool = True) -> bool:
    if val is None:
        return default
    return val.strip().lower() in {"1", "true", "yes", "on"}


def apply_dynamic_performance(*, force: bool | None = None) -> CapacityPlan:
    """Probe host and apply recommended env knobs (clears Settings cache)."""
    global _last_plan
    enabled = _truthy(os.environ.get("DYNAMIC_PERF_ENABLED"), True)
    if not enabled:
        plan = CapacityPlan(profile="manual", snapshot=probe_host(), notes=["DYNAMIC_PERF_ENABLED=false"])
        _last_plan = plan
        return plan

    with _apply_lock:
        plan = build_capacity_plan()
        force_apply = _truthy(os.environ.get("DYNAMIC_PERF_FORCE"), False) if force is None else force
        # Responsive mode is deliberately respect-env: dynamic host probing may
        # reduce work through the live plan, but must never raise explicit ceilings.
        policy_mode = (os.environ.get("PERF_POLICY_MODE") or "responsive").strip().lower()
        if policy_mode in {"responsive", "respect_env", "sequential"}:
            force_apply = False
        locked = {
            k.strip()
            for k in (os.environ.get("DYNAMIC_PERF_LOCK") or "").split(",")
            if k.strip()
        }
        applied = 0
        for key, value in plan.env.items():
            if key in locked:
                continue
            if not force_apply and key in os.environ and os.environ.get(key, "").strip() != "":
                # Keep explicit user env unless force mode
                continue
            os.environ[key] = value
            applied += 1
        try:
            from app.config import get_settings

            get_settings.cache_clear()
        except Exception:
            pass
        plan.notes.append(f"applied {applied}/{len(plan.env)} knobs (force={force_apply})")
        log.info(
            "Dynamic performance profile=%s applied=%s notes=%s",
            plan.profile,
            applied,
            "; ".join(plan.notes),
        )
        _last_plan = plan
        return plan


def get_last_plan() -> CapacityPlan | None:
    return _last_plan


def cpu_thermal_pace() -> float:
    """1.0 = full speed; lower when CPU is hot or load is saturated."""
    snap = probe_host()
    pace = 1.0
    try:
        from app.config import get_settings

        throttle_c = int(getattr(get_settings(), "cpu_thermal_throttle_c", 86) or 86)
        pause_c = int(getattr(get_settings(), "cpu_thermal_pause_c", 94) or 94)
    except Exception:
        throttle_c, pause_c = 86, 94
    if snap.cpu_temp_c is not None:
        if snap.cpu_temp_c >= pause_c:
            pace = 0.15
        elif snap.cpu_temp_c >= pause_c - 3:
            pace = 0.30
        elif snap.cpu_temp_c >= throttle_c:
            pace = 0.50
        elif snap.cpu_temp_c >= throttle_c - 5:
            pace = 0.75
    if snap.load_1m is not None and snap.cpu_logical:
        ratio = snap.load_1m / max(snap.cpu_logical, 1)
        if ratio >= 1.2:
            pace = min(pace, 0.35)
        elif ratio >= 0.95:
            pace = min(pace, 0.60)
    return pace


if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO)
    plan = apply_dynamic_performance()
    print(plan.to_dict())
