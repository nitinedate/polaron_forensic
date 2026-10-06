"""GPU temperature monitoring and adaptive thermal throttling (laptop shutdown prevention)."""

from __future__ import annotations

import logging
import shutil
import subprocess
import threading
import time
from collections import deque
from contextlib import contextmanager
from dataclasses import dataclass
from typing import Any, Iterator

log = logging.getLogger("gpu_thermal")




def release_gpu_model_after_task_enabled() -> bool:
    """Whether a worker should drop resident CUDA models after its GPU lease.

    Shared-host deployments default to true so isolated Disk/Android/iOS workers
    cannot retain VRAM after releasing the distributed GPU semaphore. Dedicated
    single-product GPU hosts may set GPU_RELEASE_MODEL_AFTER_TASK=false to keep
    warm models resident for lower latency.
    """
    import os

    raw = os.environ.get("GPU_RELEASE_MODEL_AFTER_TASK")
    if raw is not None:
        return str(raw).strip().lower() not in {"0", "false", "no", "off"}
    shared = str(os.environ.get("AETHERIS_SHARE_HOST", "true")).strip().lower()
    return shared not in {"0", "false", "no", "off"}

class GpuThermalAbort(Exception):
    """GPU exceeded safe temperature — caller should pause work and resume when cool."""

_nvml_initialized = False
_nvml_lock = threading.Lock()
_embed_batch_counter = 0
_duty_lock = threading.Lock()
_power_limit_applied: int | None = None
_temp_history: deque[tuple[float, int]] = deque(maxlen=12)
_last_thermal_log_at = 0.0


@dataclass
class GpuStats:
    available: bool
    temperature_c: int | None = None
    utilization_pct: int | None = None
    memory_used_mb: int | None = None
    memory_total_mb: int | None = None
    power_w: float | None = None
    name: str | None = None
    hot: bool = False
    throttling: bool = False
    pause_threshold_c: int = 76
    resume_threshold_c: int = 66
    throttle_threshold_c: int = 70
    source: str = "none"

    def to_dict(self) -> dict[str, Any]:
        return {
            "available": self.available,
            "temperature_c": self.temperature_c,
            "utilization_pct": self.utilization_pct,
            "memory_used_mb": self.memory_used_mb,
            "memory_total_mb": self.memory_total_mb,
            "power_w": self.power_w,
            "name": self.name,
            "hot": self.hot,
            "throttling": self.throttling,
            "pause_threshold_c": self.pause_threshold_c,
            "resume_threshold_c": self.resume_threshold_c,
            "throttle_threshold_c": self.throttle_threshold_c,
            "source": self.source,
        }


@dataclass(frozen=True)
class ThermalSettings:
    enabled: bool
    pause_c: int
    resume_c: int
    throttle_c: int
    poll_sec: float
    hot_sleep_sec: float
    embed_rest_sec: float
    duty_batches: int
    duty_rest_sec: float
    adaptive_batch: bool
    power_limit_w: int | None
    start_max_c: int
    cool_boost_c: int
    cool_batch_multiplier: float
    fallback_duty: bool
    rise_delta_c: int
    rise_window_sec: float
    abort_c: int = 90


def _record_temp(temp: int | None) -> None:
    if temp is None:
        return
    now = time.time()
    _temp_history.append((now, temp))


def _temp_rising_fast(settings: ThermalSettings) -> bool:
    """True when GPU temp climbed quickly — throttle before hard shutdown."""
    if len(_temp_history) < 2:
        return False
    now = time.time()
    window = max(settings.rise_window_sec, 5.0)
    oldest = None
    for ts, temp in _temp_history:
        if now - ts <= window:
            oldest = temp
            break
    if oldest is None:
        return False
    latest = _temp_history[-1][1]
    return (latest - oldest) >= settings.rise_delta_c


def _thermal_pace(temp: int | None, settings: ThermalSettings) -> float:
    """1.0 = full speed (cool GPU), lower = more conservative."""
    if temp is None:
        return 0.85 if settings.fallback_duty else 1.0
    if temp >= settings.pause_c:
        return 0.0
    if temp >= settings.throttle_c:
        return 0.30
    if temp >= settings.throttle_c - 3:
        return 0.55
    if temp <= settings.cool_boost_c:
        return 1.0
    span = max(settings.throttle_c - 3 - settings.cool_boost_c, 1)
    return 0.55 + 0.45 * (settings.throttle_c - 3 - temp) / span


def recommended_parallel_workers(max_workers: int, *, min_workers: int = 1) -> int:
    """Scale CPU/thread parallelism down when GPU/CPU is warm (thermal shutdown prevention)."""
    max_workers = max(int(max_workers or 1), 1)
    min_workers = max(int(min_workers or 1), 1)
    try:
        stats = get_gpu_stats()
        settings = _load_settings(gpu_name=stats.name)
        pace = _thermal_pace(stats.temperature_c if stats.available else None, settings)
        # Also respect CPU chassis heat.
        try:
            from app.services.host_capacity import cpu_thermal_pace

            pace = min(pace, float(cpu_thermal_pace()))
        except Exception:
            pass
        if pace <= 0.0:
            return min_workers
        if pace <= 0.30:
            return max(min_workers, min(2, max_workers))
        if pace <= 0.55:
            return max(min_workers, max(2, int(max_workers * 0.5)))
        if pace >= 1.0:
            return max_workers
        return max(min_workers, int(round(max_workers * (0.55 + 0.45 * pace))))
    except Exception:
        return max(min_workers, min(max_workers, 4))


def recommended_ocr_batch_limit(configured: int) -> int:
    """Shrink OCR batch when warm; allow full configured size when cool."""
    configured = max(int(configured or 20), 1)
    try:
        stats = get_gpu_stats()
        settings = _load_settings(gpu_name=stats.name)
        pace = _thermal_pace(stats.temperature_c if stats.available else None, settings)
        if pace <= 0.0:
            return max(2, min(configured, 4))
        if pace <= 0.30:
            return max(4, min(configured, 10))
        if pace <= 0.55:
            return max(10, min(configured, 20))
        if pace >= 1.0:
            return min(configured, 40)
        return min(configured, 30)
    except Exception:
        return min(configured, 24)


def _effective_embed_rest(temp: int | None, settings: ThermalSettings) -> float:
    pace = _thermal_pace(temp, settings)
    if pace >= 1.0:
        return max(settings.embed_rest_sec * 0.15, 0.08)
    if pace <= 0.30:
        return max(settings.embed_rest_sec, settings.hot_sleep_sec)
    return settings.embed_rest_sec * (0.20 + 0.80 * pace)


def _effective_duty_batches(temp: int | None, settings: ThermalSettings) -> int:
    """Sprint when cool (many batches, short rests); pulse when warm."""
    pace = _thermal_pace(temp, settings)
    base = max(settings.duty_batches, 1)
    if pace >= 1.0:
        return max(base * 2, 10)
    if pace <= 0.30:
        return max(2, base // 2)
    if pace <= 0.55:
        return max(3, int(base * 0.75))
    return base


def _effective_duty_rest(temp: int | None, settings: ThermalSettings) -> float:
    pace = _thermal_pace(temp, settings)
    if pace >= 1.0:
        # Cool sprint — keep duty rests short so embeds stay busy.
        return max(settings.duty_rest_sec * 0.25, 0.8)
    if pace <= 0.30:
        return settings.duty_rest_sec * 2.0
    if pace <= 0.55:
        return settings.duty_rest_sec * 1.25
    return settings.duty_rest_sec * (0.35 + 0.50 * pace)


def _clamp_laptop_ceilings(settings: ThermalSettings, gpu_name: str | None) -> ThermalSettings:
    """Hard ceiling for laptop/mobile GPUs — OEM shutdown often hits ~85°C.

    Cool-path stays fast (higher start/cool windows); only hot-path ceilings are hard.
    When GPU_THERMAL_HONOR_ENV=true, keep user .env ceilings (still never raise above them).
    """
    import re

    name = (gpu_name or "").lower()
    laptopish = bool(re.search(r"laptop|mobile|max-q|geforce\s*rtx\s*\d{4}\s*laptop", name))
    if not name:
        laptopish = True  # unknown → conservative
    if not laptopish:
        return settings
    honor_env = True
    try:
        from app.config import get_settings

        honor_env = bool(getattr(get_settings(), "gpu_thermal_honor_env", True))
    except Exception:
        honor_env = True
    if honor_env:
        # Honor user .env. Never raise abort into the OEM shutdown band (~95–100°C).
        return ThermalSettings(
            enabled=settings.enabled,
            pause_c=min(settings.pause_c, 92),
            resume_c=min(settings.resume_c, 86),
            throttle_c=min(settings.throttle_c, 88),
            poll_sec=settings.poll_sec,
            hot_sleep_sec=settings.hot_sleep_sec,
            embed_rest_sec=settings.embed_rest_sec,
            duty_batches=settings.duty_batches,
            duty_rest_sec=settings.duty_rest_sec,
            adaptive_batch=settings.adaptive_batch,
            # Cool-path ceiling. 5070 Ti Laptop is starved at 70–90W; abort/pause still apply.
            power_limit_w=min(int(settings.power_limit_w or 120), 140) if settings.power_limit_w else settings.power_limit_w,
            start_max_c=min(settings.start_max_c, 92),
            cool_boost_c=settings.cool_boost_c,
            cool_batch_multiplier=settings.cool_batch_multiplier,
            fallback_duty=settings.fallback_duty,
            rise_delta_c=settings.rise_delta_c,
            rise_window_sec=settings.rise_window_sec,
            abort_c=min(settings.abort_c, 94),
        )
    return ThermalSettings(
        enabled=settings.enabled,
        pause_c=min(settings.pause_c, 74),
        resume_c=min(settings.resume_c, 64),
        throttle_c=min(settings.throttle_c, 70),
        poll_sec=min(settings.poll_sec, 2.5),
        # Allow lighter cool-path sleeps; hot path still uses max(hot_sleep, …) in guards.
        hot_sleep_sec=max(min(settings.hot_sleep_sec, 8.0), 3.0),
        embed_rest_sec=max(min(settings.embed_rest_sec, 1.5), 0.4),
        duty_batches=min(max(settings.duty_batches, 1), 6),
        duty_rest_sec=max(min(settings.duty_rest_sec, 6.0), 2.0),
        adaptive_batch=settings.adaptive_batch,
        # Cap at 80W; adaptive_power_limit() drops further when warm/hot.
        power_limit_w=min(int(settings.power_limit_w or 70), 80),
        # Don't idle at 55°C — 3070 Ti Laptop is fine starting work into the low 60s.
        start_max_c=min(max(settings.start_max_c, 55), 64),
        cool_boost_c=min(max(settings.cool_boost_c, 50), 60),
        cool_batch_multiplier=min(settings.cool_batch_multiplier, 1.35),
        fallback_duty=True,
        rise_delta_c=min(settings.rise_delta_c, 6),
        rise_window_sec=min(settings.rise_window_sec, 15.0),
        abort_c=min(settings.abort_c, 78),
    )


def _load_settings(*, gpu_name: str | None = None) -> ThermalSettings:
    try:
        from app.config import get_settings

        s = get_settings()
        power = getattr(s, "gpu_thermal_power_limit_w", None)
        raw = ThermalSettings(
            enabled=bool(getattr(s, "gpu_thermal_enabled", True)),
            pause_c=int(getattr(s, "gpu_thermal_pause_c", 92) or 92),
            resume_c=int(getattr(s, "gpu_thermal_resume_c", 84) or 84),
            throttle_c=int(getattr(s, "gpu_thermal_throttle_c", 87) or 87),
            poll_sec=float(getattr(s, "gpu_thermal_poll_sec", 2.0) or 2.0),
            hot_sleep_sec=float(getattr(s, "gpu_thermal_hot_batch_sleep_sec", 6.0) or 6.0),
            embed_rest_sec=float(getattr(s, "gpu_thermal_embed_rest_sec", 1.0) or 1.0),
            duty_batches=int(getattr(s, "gpu_thermal_duty_cycle_batches", 3) or 3),
            duty_rest_sec=float(getattr(s, "gpu_thermal_duty_cycle_rest_sec", 5.0) or 5.0),
            adaptive_batch=bool(getattr(s, "gpu_thermal_adaptive_batch", True)),
            power_limit_w=int(power) if power else 70,
            start_max_c=int(getattr(s, "gpu_thermal_start_max_c", 90) or 90),
            cool_boost_c=int(getattr(s, "gpu_thermal_cool_boost_c", 50) or 50),
            cool_batch_multiplier=float(getattr(s, "gpu_thermal_cool_batch_multiplier", 1.10) or 1.10),
            fallback_duty=bool(getattr(s, "gpu_thermal_fallback_duty", True)),
            rise_delta_c=int(getattr(s, "gpu_thermal_rise_delta_c", 5) or 5),
            rise_window_sec=float(getattr(s, "gpu_thermal_rise_window_sec", 15.0) or 15.0),
            abort_c=int(getattr(s, "gpu_thermal_abort_c", 94) or 94),
        )
    except Exception:
        raw = ThermalSettings(
            enabled=True,
            pause_c=92,
            resume_c=84,
            throttle_c=87,
            poll_sec=2.0,
            hot_sleep_sec=6.0,
            embed_rest_sec=1.0,
            duty_batches=3,
            duty_rest_sec=5.0,
            adaptive_batch=True,
            power_limit_w=70,
            start_max_c=90,
            cool_boost_c=50,
            cool_batch_multiplier=1.10,
            fallback_duty=True,
            rise_delta_c=5,
            rise_window_sec=15.0,
            abort_c=94,
        )
    # Ordering: throttle ≤ pause ≤ abort. pause==abort==90 is allowed.
    pause_c = raw.pause_c
    abort_c = max(raw.abort_c, pause_c)
    throttle_c = min(raw.throttle_c, max(pause_c - 5, 50))
    start_max = min(raw.start_max_c, pause_c)
    resume_c = min(raw.resume_c, max(pause_c - 5, 45))
    ordered = ThermalSettings(
        enabled=raw.enabled,
        pause_c=pause_c,
        resume_c=max(resume_c, 45),
        throttle_c=max(throttle_c, 50),
        poll_sec=raw.poll_sec,
        hot_sleep_sec=raw.hot_sleep_sec,
        embed_rest_sec=raw.embed_rest_sec,
        duty_batches=raw.duty_batches,
        duty_rest_sec=raw.duty_rest_sec,
        adaptive_batch=raw.adaptive_batch,
        power_limit_w=raw.power_limit_w,
        start_max_c=max(start_max, 45),
        cool_boost_c=raw.cool_boost_c,
        cool_batch_multiplier=raw.cool_batch_multiplier,
        fallback_duty=raw.fallback_duty,
        rise_delta_c=raw.rise_delta_c,
        rise_window_sec=raw.rise_window_sec,
        abort_c=abort_c,
    )
    return _clamp_laptop_ceilings(ordered, gpu_name)


def _read_via_nvidia_smi() -> GpuStats | None:
    exe = shutil.which("nvidia-smi")
    if not exe:
        return None
    try:
        out = subprocess.check_output(
            [
                exe,
                "--query-gpu=name,temperature.gpu,utilization.gpu,memory.used,memory.total,power.draw",
                "--format=csv,noheader,nounits",
            ],
            text=True,
            timeout=5,
            stderr=subprocess.DEVNULL,
        ).strip()
        if not out:
            return None
        line = out.splitlines()[0]
        parts = [p.strip() for p in line.split(",")]
        if len(parts) < 6:
            return None
        name, temp_s, util_s, mem_used_s, mem_total_s, power_s = parts[:6]
        temp = int(float(temp_s)) if temp_s not in ("", "[N/A]") else None
        util = int(float(util_s)) if util_s not in ("", "[N/A]") else None
        mem_used = int(float(mem_used_s)) if mem_used_s not in ("", "[N/A]") else None
        mem_total = int(float(mem_total_s)) if mem_total_s not in ("", "[N/A]") else None
        power = float(power_s) if power_s not in ("", "[N/A]") else None
        return GpuStats(
            available=True,
            temperature_c=temp,
            utilization_pct=util,
            memory_used_mb=mem_used,
            memory_total_mb=mem_total,
            power_w=power,
            name=name,
            source="nvidia-smi",
        )
    except Exception as exc:
        log.debug("nvidia-smi thermal read failed: %s", exc)
        return None


def _read_via_pynvml() -> GpuStats | None:
    global _nvml_initialized
    try:
        import pynvml
    except ImportError:
        return None
    box: dict[str, Any] = {}

    def _read() -> None:
        global _nvml_initialized
        try:
            with _nvml_lock:
                if not _nvml_initialized:
                    pynvml.nvmlInit()
                    _nvml_initialized = True
                handle = pynvml.nvmlDeviceGetHandleByIndex(0)
                name = pynvml.nvmlDeviceGetName(handle)
                if isinstance(name, bytes):
                    name = name.decode("utf-8", errors="replace")
                temp = int(pynvml.nvmlDeviceGetTemperature(handle, pynvml.NVML_TEMPERATURE_GPU))
                util = pynvml.nvmlDeviceGetUtilizationRates(handle)
                mem = pynvml.nvmlDeviceGetMemoryInfo(handle)
                power_mw = pynvml.nvmlDeviceGetPowerUsage(handle)
                box["stats"] = GpuStats(
                    available=True,
                    temperature_c=temp,
                    utilization_pct=int(util.gpu),
                    memory_used_mb=int(mem.used // (1024 * 1024)),
                    memory_total_mb=int(mem.total // (1024 * 1024)),
                    power_w=round(power_mw / 1000.0, 1) if power_mw else None,
                    name=name,
                    source="pynvml",
                )
        except Exception as exc:
            box["error"] = exc

    worker = threading.Thread(target=_read, name="pynvml-read", daemon=True)
    worker.start()
    worker.join(3.0)
    if worker.is_alive():
        log.warning("pynvml thermal read hung — falling back to nvidia-smi")
        return None
    if box.get("error") is not None:
        log.debug("pynvml thermal read failed: %s", box["error"])
        return None
    return box.get("stats")


def _apply_power_limit_watts(watts: int) -> None:
    """Set nvidia-smi -pl if the value changed."""
    global _power_limit_applied
    watts = max(int(watts), 30)
    if _power_limit_applied == watts:
        return
    exe = shutil.which("nvidia-smi")
    if not exe:
        return
    try:
        subprocess.check_call(
            [exe, "-pl", str(watts)],
            timeout=10,
            stderr=subprocess.DEVNULL,
            stdout=subprocess.DEVNULL,
        )
        prev = _power_limit_applied
        _power_limit_applied = watts
        log.info("GPU power limit %sW → %sW (thermal/performance balance)", prev, watts)
    except Exception as exc:
        log.debug("Could not set GPU power limit: %s", exc)


def _apply_power_limit_if_configured(settings: ThermalSettings) -> None:
    """Apply configured ceiling as the cool-path power budget."""
    if not settings.power_limit_w or settings.power_limit_w <= 0:
        return
    _apply_power_limit_watts(int(settings.power_limit_w))


def adaptive_power_limit(*, settings: ThermalSettings | None = None, temp_c: int | None = None) -> int | None:
    """Scale GPU power with temperature — fast when cool, safe when hot.

    Returns the watts applied (or None if unavailable).
    """
    settings = settings or _load_settings()
    if not settings.enabled or not settings.power_limit_w:
        return None
    ceiling = int(settings.power_limit_w)
    if temp_c is None:
        stats = get_gpu_stats()
        temp_c = stats.temperature_c if stats.available else None
    if temp_c is None:
        _apply_power_limit_watts(ceiling)
        return ceiling

    # Bands for RTX 30/40 laptop GPUs — keep headroom under OEM trip (~85°C).
    if temp_c >= settings.abort_c - 2:
        target = min(ceiling, 45)
    elif temp_c >= settings.pause_c:
        target = min(ceiling, 50)
    elif temp_c >= settings.throttle_c:
        target = min(ceiling, max(55, int(ceiling * 0.75)))
    elif temp_c >= settings.cool_boost_c:
        target = min(ceiling, max(60, int(ceiling * 0.90)))
    else:
        target = ceiling  # cool → full configured budget
    _apply_power_limit_watts(target)
    return target


def get_gpu_stats() -> GpuStats:
    raw = _read_via_pynvml() or _read_via_nvidia_smi()
    settings = _load_settings(gpu_name=(raw.name if raw else None))
    if not raw:
        return GpuStats(
            available=False,
            pause_threshold_c=settings.pause_c,
            resume_threshold_c=settings.resume_c,
            throttle_threshold_c=settings.throttle_c,
        )
    raw.pause_threshold_c = settings.pause_c
    raw.resume_threshold_c = settings.resume_c
    raw.throttle_threshold_c = settings.throttle_c
    if settings.enabled and raw.temperature_c is not None:
        raw.hot = raw.temperature_c >= settings.pause_c
        raw.throttling = raw.temperature_c >= settings.throttle_c
        _record_temp(raw.temperature_c)
    return raw


def is_gpu_hot() -> bool:
    stats = get_gpu_stats()
    return bool(stats.available and stats.hot)


def adaptive_embed_batch_size(base: int, *, gpu: bool = True) -> int:
    """Scale embedding batch size down when hot, up slightly when cool."""
    base = max(int(base or 1), 1)
    if not gpu:
        return min(base, 4)
    settings = _load_settings()
    if not settings.enabled or not settings.adaptive_batch:
        return base
    stats = get_gpu_stats()
    if not stats.available or stats.temperature_c is None:
        # No sensor — stay conservative to avoid blind thermal runaway.
        return max(4, int(base * 0.75)) if settings.fallback_duty else base
    temp = stats.temperature_c
    cap = base
    try:
        from app.config import get_settings

        cap = int(getattr(get_settings(), "rag_batch_size_cap", base) or base)
    except Exception:
        pass
    cap = max(cap, base)

    if temp >= settings.pause_c:
        return max(1, base // 4)
    if temp >= settings.throttle_c:
        return max(2, base // 2)
    if temp >= settings.throttle_c - 3:
        return max(4, int(base * 0.70))
    if _temp_rising_fast(settings):
        return max(4, int(base * 0.65))
    if temp <= settings.cool_boost_c:
        boosted = int(base * settings.cool_batch_multiplier)
        return min(max(boosted, base), cap)
    return base


def wait_for_gpu_cooldown(*, reason: str = "gpu_work", max_wait_sec: float | None = None) -> float:
    """Block while at/above pause. Resume as soon as temp drops under pause (not resume_c).

    Laptop idle temps often sit at 70–77°C, so waiting for resume_c=62°C never ends
    and OCR/RAG appear stuck on the same queue forever.
    """
    settings = _load_settings()
    if not settings.enabled:
        return 0.0

    waited = 0.0
    if max_wait_sec is None:
        max_wait_sec = 90.0
    deadline = time.time() + max_wait_sec if max_wait_sec > 0 else None
    stats = get_gpu_stats()
    if not stats.available or stats.temperature_c is None:
        return 0.0
    if stats.temperature_c < settings.pause_c:
        return 0.0

    clear_c = max(settings.pause_c - 2, min(settings.resume_c, settings.pause_c - 2))
    log.warning(
        "GPU thermal pause (%s): %s°C >= %s°C — waiting to drop below %s°C (max %.0fs)",
        reason,
        stats.temperature_c,
        settings.pause_c,
        clear_c,
        max_wait_sec or 0,
    )
    while True:
        if deadline and time.time() >= deadline:
            log.warning(
                "GPU thermal wait timeout (%s) after %.0fs at %s°C — continuing",
                reason,
                waited,
                stats.temperature_c,
            )
            break
        time.sleep(max(settings.poll_sec, 1.0))
        waited += settings.poll_sec
        stats = get_gpu_stats()
        if not stats.available or stats.temperature_c is None:
            break
        if stats.temperature_c < settings.pause_c or stats.temperature_c <= clear_c:
            log.info("GPU cooled to %s°C — resuming %s", stats.temperature_c, reason)
            break
        if int(waited) % 30 == 0:
            log.warning("Still cooling GPU: %s°C (target <%s°C)", stats.temperature_c, settings.pause_c)
    return waited


def wait_for_gpu_start_window(*, reason: str = "gpu_work", max_wait_sec: float = 90.0) -> float:
    """Wait only when already at/above pause. Do not require start_max_c (often unreachable)."""
    settings = _load_settings()
    if not settings.enabled:
        return 0.0
    stats = get_gpu_stats()
    if not stats.available or stats.temperature_c is None:
        return 0.0
    if stats.temperature_c < settings.pause_c:
        return 0.0
    log.warning(
        "GPU at pause for %s: %s°C >= %s°C — short wait before start",
        reason,
        stats.temperature_c,
        settings.pause_c,
    )
    return wait_for_gpu_cooldown(reason=reason, max_wait_sec=max_wait_sec)


def _maybe_log_thermal_state(batch_num: int, temp: int | None, sleep_for: float, settings: ThermalSettings) -> None:
    global _last_thermal_log_at
    now = time.time()
    if batch_num % 20 != 0 and (now - _last_thermal_log_at) < 60:
        return
    _last_thermal_log_at = now
    stats = get_gpu_stats()
    log.info(
        "GPU thermal batch=%d temp=%s°C power=%sW util=%s%% rest=%.1fs pace=%.0f%%",
        batch_num,
        temp if temp is not None else "?",
        stats.power_w if stats.available else "?",
        stats.utilization_pct if stats.available else "?",
        sleep_for,
        _thermal_pace(temp, settings) * 100,
    )


def thermal_guard_before_batch(*, reason: str = "embed") -> None:
    """Call before each GPU batch — wait if hot, slow down if warm."""
    # Heartbeat the cross-worker exclusive GPU slot (RAG/OCR).
    try:
        from app.services.job_locks import refresh_gpu_heavy_slot

        refresh_gpu_heavy_slot()
    except Exception:
        pass

    stats = get_gpu_stats()
    settings = _load_settings(gpu_name=stats.name)
    if not settings.enabled:
        return

    # Performance when cool, cut power when warm — before any sleep/abort checks.
    try:
        adaptive_power_limit(settings=settings, temp_c=stats.temperature_c)
    except Exception:
        pass

    # Chassis: CPU throttle (~80°C) with a cool GPU is OCR Agent's to keep working.
    try:
        from app.services.agent_duties import assess_chassis_for_ocr
        from app.services.host_capacity import probe_host

        snap = probe_host()
        cpu_c = snap.cpu_temp_c
        gpu_c = stats.temperature_c if stats.available else None
        advice = assess_chassis_for_ocr(gpu_c, cpu_c)
        if not advice["ocr_may_run"]:
            raise GpuThermalAbort(advice["reason"])
        # Do not sleep on CPU-only throttle. That used to freeze OCR for an hour
        # at ~80°C CPU / ~55°C GPU. GPU throttle still sleeps below.
        if advice["cpu_throttle_only"] or advice.get("cpu_warm_gpu_cool"):
            pass
        elif advice["slow_batches"] and (
            gpu_c is None or gpu_c < settings.throttle_c
        ):
            time.sleep(max(settings.hot_sleep_sec * 0.25, 0.4))
    except GpuThermalAbort:
        raise
    except Exception:
        pass

    if not stats.available or stats.temperature_c is None:
        if settings.fallback_duty:
            time.sleep(settings.embed_rest_sec * 0.5)
        return
    temp = stats.temperature_c
    if temp >= settings.abort_c:
        raise GpuThermalAbort(
            f"GPU {temp}°C reached abort threshold ({settings.abort_c}°C) — pausing to prevent thermal shutdown"
        )
    if temp >= settings.pause_c:
        wait_for_gpu_cooldown(reason=reason)
        return
    # Only preempt on rapid rise when already near throttle — early rises (e.g. 55→61)
    # are normal warm-up and were starving throughput with long sleeps.
    rise_gate = max(settings.throttle_c - 4, settings.cool_boost_c + 4)
    if temp >= rise_gate and _temp_rising_fast(settings):
        log.warning("GPU temp rising fast (%s°C) — preemptive cooldown", temp)
        time.sleep(settings.hot_sleep_sec)
        return
    if temp >= settings.throttle_c:
        time.sleep(settings.hot_sleep_sec)
        return
    if temp <= settings.cool_boost_c:
        return
    warn_c = max(settings.resume_c + 2, settings.throttle_c - 2)
    if temp >= warn_c and settings.hot_sleep_sec > 0:
        time.sleep(settings.hot_sleep_sec * 0.25)


def thermal_guard_after_batch(*, reason: str = "embed") -> None:
    """Micro-rest after each embed batch + periodic duty-cycle cooldown (scales with GPU temp)."""
    global _embed_batch_counter
    settings = _load_settings()
    if not settings.enabled:
        return

    stats = get_gpu_stats()
    temp = stats.temperature_c if stats.available else None
    is_ocr = str(reason or "").startswith(("glm_ocr", "ocr"))
    # OCR already spends seconds per page in GLM generate. Do not add embed
    # duty-cycle sleeps while the GPU is cool — that stretched 7h drains.
    if is_ocr and (temp is None or temp < settings.throttle_c):
        return

    with _duty_lock:
        _embed_batch_counter += 1
        batch_num = _embed_batch_counter
        duty_every = _effective_duty_batches(temp, settings)
        at_duty_rest = duty_every > 0 and batch_num % duty_every == 0

    sleep_for = _effective_embed_rest(temp, settings)

    if temp is not None:
        if temp >= settings.pause_c:
            sleep_for = max(sleep_for, settings.hot_sleep_sec * 2)
        elif temp >= settings.throttle_c:
            extra = min(8.0, (temp - settings.throttle_c) * 1.5)
            sleep_for = max(sleep_for, settings.hot_sleep_sec + extra)
        elif temp >= max(settings.throttle_c - 4, settings.cool_boost_c + 4) and _temp_rising_fast(settings):
            sleep_for = max(sleep_for, settings.hot_sleep_sec * 0.75)
    elif settings.fallback_duty:
        sleep_for = max(sleep_for, settings.embed_rest_sec)

    if at_duty_rest:
        duty_rest = _effective_duty_rest(temp, settings)
        sleep_for = max(sleep_for, duty_rest)
        if duty_rest >= 1.5:
            log.info(
                "GPU duty-cycle rest %.1fs after %d embed batches (temp=%s°C, pace=%.0f%%)",
                sleep_for,
                duty_every,
                temp if temp is not None else "?",
                _thermal_pace(temp, settings) * 100,
            )

    # Also respect host CPU room — laptops often hit CPU thermal before GPU.
    try:
        from app.services.host_capacity import cpu_thermal_pace

        cpu_pace = cpu_thermal_pace()
        if cpu_pace < 1.0:
            sleep_for = max(sleep_for, (1.0 - cpu_pace) * max(settings.hot_sleep_sec, 2.0))
    except Exception:
        pass

    _maybe_log_thermal_state(batch_num, temp, sleep_for, settings)

    if sleep_for > 0:
        time.sleep(sleep_for)


def gpu_log_prefix(*, include_temp: bool = True) -> str:
    """Short GPU status prefix for job logs — e.g. '[GPU RTX 4060 62°C]'."""
    stats = get_gpu_stats()
    if not stats.available:
        return "[CPU — no GPU detected]"
    parts: list[str] = []
    if stats.name:
        parts.append(stats.name.split()[-1] if len(stats.name.split()) > 1 else stats.name)
    if include_temp and stats.temperature_c is not None:
        parts.append(f"{stats.temperature_c}°C")
    label = " ".join(parts) if parts else "GPU"
    return f"[GPU {label}]"


def gpu_work_log_message(message: str, *, include_temp: bool = True) -> str:
    """Prefix a log line with current GPU status when a GPU is available."""
    prefix = gpu_log_prefix(include_temp=include_temp)
    if prefix.startswith("[CPU"):
        return message
    return f"{prefix} {message}"


def prepare_gpu_for_heavy_work(
    *,
    reason: str = "rag_index",
    unload_ollama: bool = True,
    wait_for_cool: bool = True,
) -> dict[str, Any]:
    """Before large GPU jobs: cap power, unload Ollama, optionally wait for safe temps.

    Prefer :func:`gpu_heavy_session` so RAG and OCR cannot overlap across workers.
    Worker entrypoints must pass wait_for_cool=False so Celery can start.
    """
    stats = get_gpu_stats()
    settings = _load_settings(gpu_name=stats.name)
    result: dict[str, Any] = {
        "reason": reason,
        "ollama_unloaded": [],
        "waited_sec": 0.0,
        "power_limit_w": settings.power_limit_w,
        "pause_c": settings.pause_c,
        "abort_c": settings.abort_c,
    }
    _apply_power_limit_if_configured(settings)
    try:
        adaptive_power_limit(settings=settings, temp_c=(stats.temperature_c if stats.available else None))
    except Exception:
        pass
    if unload_ollama:
        try:
            from app.services.model_router import ollama_unload_all_models

            result["ollama_unloaded"] = ollama_unload_all_models()
            if result["ollama_unloaded"]:
                log.info("Unloaded Ollama models before %s: %s", reason, result["ollama_unloaded"])
                time.sleep(3)
        except Exception as exc:
            log.debug("Ollama unload skipped: %s", exc)
    # Swap resident GPU models so OCR and RAG never share VRAM in one worker.
    reason_l = (reason or "").lower()
    try:
        if "ocr" in reason_l or "glm" in reason_l:
            from app.services.embedding_gpu import unload_embedder

            result["embedder_unloaded"] = bool(unload_embedder())
        else:
            from app.services.ocr_gpu import unload_glm_ocr

            result["ocr_unloaded"] = bool(unload_glm_ocr())
    except Exception as exc:
        log.debug("Cross-model GPU unload skipped before %s: %s", reason, exc)
    if wait_for_cool:
        result["waited_sec"] = wait_for_gpu_start_window(reason=reason, max_wait_sec=90.0)
    result["stats"] = get_gpu_stats().to_dict()
    return result


@contextmanager
def gpu_heavy_session(reason: str = "rag_index", *, unload_ollama: bool = True) -> Iterator[dict[str, Any]]:
    """Exclusive GPU session across Celery workers (RAG XOR OCR).

    Prevents laptop thermal shutdown when extract/embed/OCR would otherwise
    pile onto the same GPU/chassis at once. Fail-closed on slot timeout.
    """
    from app.services.job_locks import gpu_heavy_slot

    with gpu_heavy_slot(reason, fail_closed=True) as acquired:
        try:
            prep = prepare_gpu_for_heavy_work(reason=reason, unload_ollama=unload_ollama)
            prep["slot_acquired"] = bool(acquired)
            yield prep
        finally:
            if release_gpu_model_after_task_enabled():
                # Cleanup occurs while the permit is still held, so another
                # product cannot enter until this process has actually returned VRAM.
                for unload in (
                    ("embedder", "app.services.embedding_gpu", "unload_embedder"),
                    ("ocr", "app.services.ocr_gpu", "unload_glm_ocr"),
                    ("clip", "app.services.image_embed", "unload_clip_model"),
                ):
                    try:
                        module = __import__(unload[1], fromlist=[unload[2]])
                        getattr(module, unload[2])()
                    except Exception as exc:
                        log.debug("GPU model cleanup skipped for %s: %s", unload[0], exc)


def reset_embed_duty_counter() -> None:
    """Reset duty-cycle counter (e.g. at start of a new RAG job)."""
    global _embed_batch_counter, _last_thermal_log_at
    with _duty_lock:
        _embed_batch_counter = 0
    _temp_history.clear()
    _last_thermal_log_at = 0.0


def should_empty_cuda_cache(*, batch_num: int) -> bool:
    """Empty CUDA cache every batch when hot; less often when cool (saves time)."""
    settings = _load_settings()
    stats = get_gpu_stats()
    if stats.available and stats.temperature_c is not None:
        if stats.temperature_c >= settings.throttle_c:
            return True
        if stats.temperature_c <= settings.cool_boost_c:
            return batch_num % 12 == 0
        return batch_num % 8 == 0
    return batch_num % 8 == 0
