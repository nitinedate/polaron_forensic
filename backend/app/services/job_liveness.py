"""Job liveness for long pipeline tasks (V45.5).

Every stall detector in the product (frontend auto-resume at 240 s, API
``/resume`` at 240 s, pipeline supervisor at ``PIPELINE_STALE_SEC`` = 55 s) was
keyed on ``jobs.updated_at``. A task is only "alive" while some code path
happens to write that column. Extraction writes it from inside a few wrapped
steps, but not while waiting for the CPU lane, opening the image, planning, or
between shard flushes — so a healthy worker reading a slow source was declared
dead and re-queued ("Extraction stalled (no progress) - re-queuing from last
checkpoint"), spawning a duplicate task that then fought for the slot.

``JobLiveness`` is one daemon thread per task that, for the task's lifetime:

* bumps ``jobs.updated_at`` every ``touch_sec`` (default 20 s), so every
  updated_at-based detector sees a heartbeat regardless of which step runs;
* refreshes the Redis job lock (``lock_kind``) every ``refresh_sec``;
* writes one ``disk_build_logs`` line every ``log_sec`` naming the current
  sub-step and its age (``<Stage> liveness - enumerate (142s in step, 300s total)``);
* keeps per-step timings for a final summary line.

Nested code marks progress without plumbing the object through:

    from app.services.job_liveness import mark_step
    mark_step(job_id, "enumerate", files=12345)      # no-op if no liveness active
"""

from __future__ import annotations

import logging
import threading
import time
from typing import Any

log = logging.getLogger("job_liveness")

_REGISTRY: dict[str, "JobLiveness"] = {}
_REGISTRY_LOCK = threading.Lock()


def current(job_id: str) -> "JobLiveness | None":
    with _REGISTRY_LOCK:
        return _REGISTRY.get(str(job_id))


def mark_step(job_id: str, name: str, **extra: Any) -> None:
    live = current(job_id)
    if live is not None:
        live.step(name, **extra)


class JobLiveness:
    def __init__(
        self,
        schema_name: str | None,
        job_id: str,
        *,
        stage: str,
        label: str,
        lock_kind: str | None = None,
        touch_sec: float = 20.0,
        refresh_sec: float = 45.0,
        log_sec: float = 90.0,
    ) -> None:
        self.schema_name = schema_name
        self.job_id = str(job_id)
        self.stage = stage
        self.label = label
        self.lock_kind = lock_kind
        self.touch_sec = max(float(touch_sec), 5.0)
        self.refresh_sec = max(float(refresh_sec), 10.0)
        self.log_sec = max(float(log_sec), 30.0)
        self._stop = threading.Event()
        self._lock = threading.Lock()
        self._thread: threading.Thread | None = None
        self._step = "starting"
        self._step_started = time.monotonic()
        self._run_started = time.monotonic()
        self._last_log = 0.0
        self._last_touch = 0.0
        self._last_refresh = 0.0
        self.timings: dict[str, float] = {}
        self.extra: dict[str, Any] = {}

    # ---------------------------------------------------------------- public
    def step(self, name: str, **extra: Any) -> None:
        now = time.monotonic()
        with self._lock:
            prev = self._step
            self.timings[prev] = self.timings.get(prev, 0.0) + (now - self._step_started)
            self._step = str(name or "step")
            self._step_started = now
            self.extra = dict(extra)
        log.info("%s job=%s step=%s", self.stage, self.job_id, name)
        # A step change is progress: make it visible immediately.
        self._touch_job(force=True)

    def current(self) -> tuple[str, float]:
        with self._lock:
            return self._step, time.monotonic() - self._step_started

    def elapsed(self) -> float:
        return time.monotonic() - self._run_started

    def summary(self) -> dict[str, float]:
        name, age = self.current()
        out = dict(self.timings)
        out[name] = out.get(name, 0.0) + age
        return {k: round(v, 1) for k, v in sorted(out.items(), key=lambda kv: -kv[1])}

    # -------------------------------------------------------------- lifecycle
    def __enter__(self) -> "JobLiveness":
        with _REGISTRY_LOCK:
            _REGISTRY[self.job_id] = self
        self._thread = threading.Thread(target=self._run, name=f"live-{self.stage}-{self.job_id[:8]}", daemon=True)
        self._thread.start()
        return self

    def __exit__(self, *exc: Any) -> None:
        self._stop.set()
        if self._thread:
            self._thread.join(timeout=3.0)
        with _REGISTRY_LOCK:
            if _REGISTRY.get(self.job_id) is self:
                _REGISTRY.pop(self.job_id, None)
        name, age = self.current()
        self.timings[name] = self.timings.get(name, 0.0) + age

    # --------------------------------------------------------------- internal
    def _touch_job(self, *, force: bool = False) -> None:
        now = time.monotonic()
        if not force and now - self._last_touch < self.touch_sec:
            return
        self._last_touch = now
        if not self.schema_name:
            return
        try:
            from app.db.session import firm_session
            from app.db.sql_helpers import execute

            with firm_session(self.schema_name) as db:
                execute(db, "UPDATE jobs SET updated_at=NOW() WHERE id=:id", {"id": self.job_id})
                db.commit()
        except Exception:
            log.debug("liveness touch failed job=%s", self.job_id, exc_info=True)

    def _refresh_lock(self) -> None:
        if not self.lock_kind:
            return
        try:
            from app.services.job_locks import refresh_job_lock

            refresh_job_lock(self.lock_kind, self.job_id)
        except Exception:
            log.debug("liveness lock refresh failed job=%s", self.job_id, exc_info=True)

    def _write_log(self) -> None:
        if not self.schema_name:
            return
        name, age = self.current()
        try:
            from app.db.session import firm_session
            from app.services.disk_build_log import write_disk_log

            with firm_session(self.schema_name) as db:
                write_disk_log(
                    db,
                    self.job_id,
                    f"{self.label} liveness - {name} ({age:,.0f}s in step, {self.elapsed():,.0f}s total)",
                    stage=self.stage,
                    metadata={
                        "liveness": True,
                        "step": name,
                        "step_sec": round(age, 1),
                        "total_sec": round(self.elapsed(), 1),
                        **{k: v for k, v in self.extra.items() if isinstance(v, (str, int, float, bool))},
                    },
                )
                db.commit()
        except Exception:
            log.debug("liveness log failed job=%s", self.job_id, exc_info=True)

    def _run(self) -> None:
        while not self._stop.wait(5.0):
            now = time.monotonic()
            self._touch_job()
            if now - self._last_refresh >= self.refresh_sec:
                self._refresh_lock()
                self._last_refresh = now
            if now - self._last_log >= self.log_sec:
                self._write_log()
                self._last_log = now

    def write_summary(self, db) -> None:
        """Final 'where did the time go' line on the caller's session."""
        try:
            from app.services.disk_build_log import write_disk_log

            summary = self.summary()
            write_disk_log(
                db,
                self.job_id,
                f"{self.label} step timings - " + ", ".join(f"{k} {v:,.0f}s" for k, v in list(summary.items())[:8]),
                stage=self.stage,
                metadata={"step_timings_sec": summary, "total_sec": round(self.elapsed(), 1)},
            )
            db.commit()
        except Exception:
            try:
                db.rollback()
            except Exception:
                pass
