"""Disk/Mobile policy: serial stages, at most four independent evidence units."""

from __future__ import annotations

from concurrent.futures import FIRST_COMPLETED, ThreadPoolExecutor, wait
from contextlib import contextmanager
from contextvars import ContextVar
from threading import BoundedSemaphore

MAX_PARALLELISM = 4
# Character windows for complete forensic evidence, including any source header.
CHUNK_SIZE = 2500
CHUNK_OVERLAP = 800
CHUNK_POLICY = "chars-2500-overlap-800-v2"
_stage_context: ContextVar[str | None] = ContextVar(
    "forensic_serial_stage", default=None
)


def serial_enabled() -> bool:
    # This policy is deliberately unrelated to PERF_POLICY_MODE or the scanner.
    from app.service_identity import VULN, current_service

    return current_service() != VULN


def parallelism(requested: int = MAX_PARALLELISM) -> int:
    return max(1, min(MAX_PARALLELISM, int(requested or 1)))


def current_stage() -> str | None:
    return _stage_context.get()


@contextmanager
def stage_context(stage: str):
    token = _stage_context.set(stage)
    try:
        yield
    finally:
        _stage_context.reset(token)


def bounded_map(fn, items, *, workers: int = MAX_PARALLELISM):
    """Bound both running work and queued inputs; never submit the whole evidence set.

    Database Sessions must be created inside fn, never shared across these threads.
    Exceptions propagate at the barrier after the executor joins its workers.
    """
    slots = parallelism(workers)
    gate = BoundedSemaphore(slots)
    source = iter(items)

    def run(item):
        with gate:
            return fn(item)

    with ThreadPoolExecutor(
        max_workers=slots, thread_name_prefix="forensic-stage"
    ) as pool:
        pending = set()
        exhausted = False
        while pending or not exhausted:
            while len(pending) < slots and not exhausted:
                try:
                    pending.add(pool.submit(run, next(source)))
                except StopIteration:
                    exhausted = True
            if not pending:
                break
            finished, pending = wait(pending, return_when=FIRST_COMPLETED)
            for future in finished:
                yield future.result()
