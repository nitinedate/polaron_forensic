"""Celery dispatcher — same AETHERIS_SERVICE switch as the API."""

from app.celery_factory import create_celery
from app.service_identity import current_service

celery = create_celery(current_service())
import app.tasks  # noqa: E402,F401

from celery.signals import worker_ready  # noqa: E402


def _worker_consumes_ocr() -> bool:
    import sys

    argv = sys.argv
    for i, part in enumerate(argv):
        if part in ("-Q", "--queues") and i + 1 < len(argv):
            return any(q.strip() == "ocr" or q.strip().endswith("-ocr") for q in argv[i + 1].split(","))
        if part.startswith("--queues="):
            return any(q.strip() == "ocr" or q.strip().endswith("-ocr") for q in part.split("=", 1)[1].split(","))
    return False


@worker_ready.connect
def _clear_stale_ocr_locks_on_start(sender=None, **kwargs) -> None:
    if not _worker_consumes_ocr():
        return
    from app.services.job_locks import clear_all_ocr_job_locks

    clear_all_ocr_job_locks()
