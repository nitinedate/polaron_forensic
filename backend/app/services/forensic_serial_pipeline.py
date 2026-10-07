"""Authoritative Disk/Mobile stage controller.

Only this controller advances stages. Celery transports a single active stage to
its product's CPU or GPU queue. PostgreSQL records retries and barriers; a session
advisory lock prevents duplicate/redelivered tasks from executing concurrently.
"""

from __future__ import annotations

import hashlib
import json
import logging
import threading
import uuid
from contextlib import contextmanager
from datetime import datetime, timezone

from app.db.sql_helpers import execute, fetchall, fetchone
from app.services.forensic_serial_policy import MAX_PARALLELISM, stage_context

log = logging.getLogger("forensic.serial")
STAGES = (
    ("intake", "Intake / preflight", "segments_agent"),
    ("source_prepare", "Source preparation", "virtual_disk_agent"),
    ("extraction", "Complete extraction", "extraction_agent"),
    ("materialize", "Register extracted artifacts", "materialize_agent"),
    ("parse", "Native forensic parsing", "parse_agent"),
    ("recovery", "Deleted / recovery analysis", "recovery_agent"),
    ("ocr", "GPU OCR", "ocr_agent"),
    ("media_review", "Image / video evidence observations", "media_review_agent"),
    ("inventory", "Normalize / correlate / artifact inventory", "artifacts_agent"),
    ("chunk", "RAG chunking", "chunk_agent"),
    ("enrichment", "Entity / annotation / ontology enrichment", "entity_agent"),
    ("graph", "Graph synchronization", "neo4j_agent"),
    ("validation", "Completeness validation", "validation_agent"),
)
TERMINAL = frozenset({"done", "skipped"})
_SCHEMA_READY: set[tuple] = set()


class StageWaiting(RuntimeError):
    """A resumable barrier, never permission to start a later stage."""


def _obj(raw):
    if isinstance(raw, str):
        return json.loads(raw) if raw else {}
    return raw if isinstance(raw, dict) else {}


def ensure_serial_schema(db) -> None:
    schema = fetchone(db, "SELECT current_schema() AS name")["name"]
    key = (str(getattr(db, "bind", "")), schema)
    if key in _SCHEMA_READY:
        return
    # These are new, small control tables. Existing evidence indexes are installed
    # concurrently by the release migration script, never by a GET request.
    execute(
        db,
        """CREATE TABLE IF NOT EXISTS pipeline_stage_runs (
        id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
        job_id uuid NOT NULL REFERENCES jobs(id) ON DELETE CASCADE,
        stage text NOT NULL, sequence_no integer NOT NULL,
        status text NOT NULL DEFAULT 'pending',
        total_items bigint NOT NULL DEFAULT 0, completed_items bigint NOT NULL DEFAULT 0,
        failed_items bigint NOT NULL DEFAULT 0, skipped_items bigint NOT NULL DEFAULT 0,
        attempt integer NOT NULL DEFAULT 0, task_id text,
        started_at timestamptz, completed_at timestamptz, heartbeat_at timestamptz,
        updated_at timestamptz NOT NULL DEFAULT NOW(),
        details jsonb NOT NULL DEFAULT '{}'::jsonb, error text,
        UNIQUE(job_id, stage), UNIQUE(job_id, sequence_no)
    )""",
    )
    execute(
        db,
        """CREATE UNIQUE INDEX IF NOT EXISTS pipeline_one_active_stage
        ON pipeline_stage_runs(job_id) WHERE status IN ('queued','running')""",
    )
    for column in ("progress_at timestamptz", "operation text", "operation_deadline timestamptz", "cancel_requested_at timestamptz", "recovery_dispatches integer NOT NULL DEFAULT 0"):
        execute(db, f"ALTER TABLE pipeline_stage_runs ADD COLUMN IF NOT EXISTS {column}")
    execute(
        db,
        """CREATE INDEX IF NOT EXISTS pipeline_stage_watchdog
        ON pipeline_stage_runs(status, updated_at) WHERE status IN ('queued','running','waiting')""",
    )
    execute(
        db,
        """CREATE TABLE IF NOT EXISTS pipeline_work_items (
        id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
        stage_run_id uuid NOT NULL REFERENCES pipeline_stage_runs(id) ON DELETE CASCADE,
        partition_key text NOT NULL, status text NOT NULL DEFAULT 'pending',
        attempt integer NOT NULL DEFAULT 0, worker_id text,
        started_at timestamptz, completed_at timestamptz,
        payload jsonb NOT NULL DEFAULT '{}'::jsonb, error text,
        UNIQUE(stage_run_id, partition_key)
    )""",
    )
    execute(
        db,
        """CREATE INDEX IF NOT EXISTS pipeline_work_pending
        ON pipeline_work_items(stage_run_id, id) WHERE status='pending'""",
    )
    from app.services.forensic_media_review import ensure_media_review_schema
    from app.services.forensic_priority_evidence import ensure_priority_schema
    ensure_priority_schema(db)
    ensure_media_review_schema(db)
    db.commit()
    _SCHEMA_READY.add(key)


def stage_rows(db, job_id: str) -> list[dict]:
    exists = fetchone(db, "SELECT to_regclass('pipeline_stage_runs') AS name")
    if not exists or not exists["name"]:
        return []
    return fetchall(
        db,
        "SELECT * FROM pipeline_stage_runs WHERE job_id=:jid ORDER BY sequence_no",
        {"jid": job_id},
    )


def upgrade_serial_layout(db, job_id: str, *, schema_name: str, force: bool = False) -> bool:
    """Replace obsolete control stages under the same lock used by workers.

    Extracted files and source evidence are retained. Old chunks are replaced by
    the next chunk pass; only derived stage claims are reset for the new parsers.
    """
    expected = [stage for stage, _, _ in STAGES]
    rows = stage_rows(db, job_id)
    if not rows or ([r["stage"] for r in rows] == expected and not force):
        return True
    with pipeline_execution_lock(db, schema_name, job_id) as acquired:
        if not acquired:
            db.rollback()
            return False
        fetchone(db, "SELECT id FROM jobs WHERE id=:id FOR UPDATE", {"id": job_id})
        execute(db, "DELETE FROM pipeline_stage_runs WHERE job_id=:jid AND stage<>ALL(:stages)",
                {"jid": job_id, "stages": expected})
        # Two passes avoid the (job_id,sequence_no) unique constraint during reorder.
        execute(db, "UPDATE pipeline_stage_runs SET sequence_no=-abs(sequence_no) WHERE job_id=:jid", {"jid": job_id})
        for seq, (stage, _, _) in enumerate(STAGES, 1):
            execute(db, "UPDATE pipeline_stage_runs SET sequence_no=:seq WHERE job_id=:jid AND stage=:stage",
                    {"jid": job_id, "stage": stage, "seq": seq})
        execute(db, """DELETE FROM pipeline_work_items WHERE stage_run_id IN
            (SELECT id FROM pipeline_stage_runs WHERE job_id=:jid AND sequence_no>=5)""", {"jid": job_id})
        execute(db, """UPDATE pipeline_stage_runs SET status='pending',task_id=NULL,error=NULL,
            completed_at=NULL,total_items=0,completed_items=0,failed_items=0,skipped_items=0,
            details='{}'::jsonb,progress_at=NULL,operation=NULL,operation_deadline=NULL,cancel_requested_at=NULL,
            recovery_dispatches=0,updated_at=NOW() WHERE job_id=:jid AND sequence_no>=5""", {"jid": job_id})
        execute(db, """UPDATE job_artifacts SET metadata=COALESCE(metadata,'{}'::jsonb)
            - 'serial_chunked' - 'serial_chunk_status' - 'serial_chunk_policy'
            - 'priority_parsed_v2' - 'priority_parsed_v4' - 'priority_parse_exception'
            - 'suspicious_activity' - 'suspicious_activity_description' WHERE job_id=:jid""", {"jid": job_id})
        if fetchone(db,"SELECT to_regclass('forensic_suspicious_activity') AS t")['t']:
            execute(db,'DELETE FROM forensic_suspicious_activity WHERE job_id=:jid',{'jid':job_id})
        if force:
            execute(db,"""UPDATE forensic_media_observations SET status='pending',error=NULL,updated_at=NOW()
                WHERE job_id=:jid AND status='failed'""",{"jid":job_id})
        execute(db, "UPDATE jobs SET status='indexing',progress_pct=0 WHERE id=:jid", {"jid": job_id})
        db.commit()
    return True


def first_open_stage(rows):
    return next((row for row in rows if row["status"] not in TERMINAL), None)


def extraction_barrier(row: dict) -> tuple[bool, str]:
    if not row or not row.get("extracted_disk_uri"):
        return False, "Waiting for the finalized extracted evidence manifest"
    ds = _obj(row.get("disk_source"))
    from app.services.host_evidence import is_client_upload_pending

    if is_client_upload_pending(ds):
        return False, "Waiting for complete client intake"
    total = int(row.get("files_total") or 0)
    done = int(row.get("files_extracted") or 0)
    # The extractor explicitly records unreadable/skipped files in its manifest.
    # They remain a completeness exception; an unknown gap blocks the barrier.
    skipped = int(ds.get("files_skipped") or 0)
    if total > done + skipped:
        return (
            False,
            f"Extraction incomplete: {done + skipped:,} / {total:,} files accounted for",
        )
    if row.get("extraction_checkpoint"):
        return False, "Extraction checkpoint has not been finalized"
    return True, "Finalized extracted evidence"


def _evidence_file_counts(row: dict, total: int, completed: int) -> tuple[int, int]:
    """Keep the parse card on the extracted file count.

    The mobile pass stores one work row per file and the stage result used to
    add that count on top of the native parse, so 26,987 files displayed as
    53,974.
    """
    if row.get("stage") != "parse":
        return total, completed
    details = _obj(row.get("details"))
    native_total = int(details.get("native_total") or 0)
    mobile = details.get("mobile")
    mobile_total = int(mobile.get("total") or 0) if isinstance(mobile, dict) else 0
    if native_total <= 0 and mobile_total > 0 and total > mobile_total:
        native_total = total - mobile_total
    if native_total > 0 and total > native_total:
        return native_total, min(completed, native_total)
    return total, completed


def snapshot_from_rows(rows: list[dict], progress: dict | None = None) -> dict:
    progress = progress or {}
    stages = []
    labels = {stage: (label, agent) for stage, label, agent in STAGES}
    upgrade_required = bool(rows) and [r["stage"] for r in rows] != list(labels)
    rows = [r for r in rows if r["stage"] in labels]
    active = first_open_stage(rows)
    for row in rows:
        label, agent = labels[row["stage"]]
        status = row["status"]
        total = int(row.get("total_items") or 0)
        completed = int(row.get("completed_items") or 0)
        failed = int(row.get("failed_items") or 0)
        skipped = int(row.get("skipped_items") or 0)
        if active and row["stage"] == active["stage"] and status == "running":
            aliases = {
                "inventory": {"artifact_inventory", "axiom_artifacts"},
                "media_review": {"media_review"},
            }
            if progress.get("phase") in aliases.get(row["stage"], {row["stage"]}):
                total = max(total, int(progress.get("total") or 0))
                completed = max(completed, int(progress.get("completed") or 0))
        total, completed = _evidence_file_counts(row, total, completed)
        pct = (
            100
            if status in TERMINAL
            else min(99, int(100 * (completed + failed + skipped) / total))
            if total
            else 0
        )
        stages.append(
            {
                "id": row["stage"],
                "agent_id": agent,
                "label": label,
                "status": status,
                "pct": pct,
                "total": total,
                "completed": completed,
                "failed": failed,
                "skipped": skipped,
                "attempt": int(row.get("attempt") or 0),
                "error": row.get("error"),
                "details": _obj(row.get("details")),
                "started_at": str(row["started_at"]) if row.get("started_at") else None,
                "completed_at": str(row["completed_at"])
                if row.get("completed_at")
                else None,
            }
        )
    complete = bool(rows) and active is None and not upgrade_required
    overall = (
        100
        if complete
        else min(99, int(sum(s["pct"] for s in stages) / max(len(stages), 1)))
    )
    return {
        "version": 2,
        "upgrade_required": upgrade_required,
        "serial": True,
        "max_parallelism": MAX_PARALLELISM,
        "current_stage": active["stage"] if active else None,
        "complete": complete,
        "overall_pct": overall,
        "stages": stages,
    }


def serial_progress_snapshot(db, job_id: str, *, row=None) -> dict | None:
    rows = stage_rows(db, job_id)
    if not rows:
        return None
    row = row or fetchone(
        db, "SELECT pipeline_progress FROM jobs WHERE id=:id", {"id": job_id}
    )
    pp = _obj((row or {}).get("pipeline_progress"))
    active_row = first_open_stage(rows)
    if active_row and active_row["status"] not in TERMINAL:
        work = fetchone(
            db,
            """SELECT count(*) AS total,count(*) FILTER (WHERE status='done') AS done,
            count(*) FILTER (WHERE status='failed') AS failed FROM pipeline_work_items WHERE stage_run_id=:sid""",
            {"sid": active_row["id"]},
        )
        if work and int(work["total"] or 0):
            native = _obj(active_row.get("details"))
            native_total = int(native.get("native_total") or 0)
            work_total = int(work["total"] or 0)
            work_done = int(work["done"] or 0)
            # Mobile bundles are the same extracted files. Adding the two
            # counts made 26,987 files display as 53,974.
            if native.get("mobile_work_active") and native_total > 0 and work_total > 0:
                active_row["total_items"] = native_total
                active_row["completed_items"] = min(
                    native_total, (native_total * work_done) // work_total
                )
            else:
                active_row["total_items"] = native_total + work_total
                active_row["completed_items"] = int(
                    native.get("native_completed") or 0
                ) + work_done
                active_row["failed_items"] = int(work["failed"] or 0)
    serial = snapshot_from_rows(rows, pp)
    agents = {}
    # Alias old UI cards to persisted stages; they never infer completion from logs.
    for s in serial["stages"]:
        state = (
            "done"
            if s["status"] in TERMINAL
            else "failed"
            if s["status"] == "failed"
            else "running"
            if s["status"] == "running"
            else "pending"
        )
        agents[s["agent_id"]] = {
            "state": state,
            "pct": s["pct"],
            "label": s["label"],
            "detail": s["error"],
            "started_at": s["started_at"],
            "finished_at": s["completed_at"],
        }
    for alias in ("annotation_agent", "ontology_agent"):
        agents[alias] = dict(agents["entity_agent"])
    for alias in ("drive_mount_agent", "download_agent", "list_folder_agent"):
        agents[alias] = {"state": "done", "pct": 100, "label": "Source prepared"}
    active = next(
        (s for s in serial["stages"] if s["id"] == serial["current_stage"]), None
    )
    pp.update(
        {
            "serial_pipeline": serial,
            "phase": active["id"] if active else "complete",
            "label": active["error"] or active["label"]
            if active
            else "Reprocess to apply updated evidence stages" if serial["upgrade_required"]
            else "Ready — completeness validated",
            "completed": active["completed"] if active else len(rows),
            "total": active["total"] if active else len(rows),
            "progress_pct": serial["overall_pct"],
            "orchestration": {
                "agents": agents,
                "overall_pct": serial["overall_pct"],
                "sequential": True,
                "current_agent_id": active["agent_id"] if active else None,
                "current_agent_label": active["label"] if active else None,
                "current_agent_state": "running"
                if active and active["status"] == "running"
                else "pending"
                if active
                else None,
            },
        }
    )
    return pp


def persist_snapshot(db, job_id: str) -> dict | None:
    pp = serial_progress_snapshot(db, job_id)
    if pp:
        execute(
            db,
            """UPDATE jobs SET pipeline_progress=COALESCE(pipeline_progress,'{}'::jsonb) || CAST(:pp AS jsonb),
            progress_pct=:pct, updated_at=NOW() WHERE id=:id""",
            {
                "id": job_id,
                "pp": json.dumps(pp, default=str),
                "pct": pp["progress_pct"],
            },
        )
    return pp


def start_serial_pipeline(
    db, job_id: str, *, schema_name: str, retry_failed: bool = False, reprocess: bool = False
) -> dict:
    from app.services.forensic_serial_policy import serial_enabled
    from app.services.mobile_platform_agents import current_service_owns_job

    if not serial_enabled() or not current_service_owns_job(db, job_id):
        return {"status": "held", "reason": "other_product"}
    row = fetchone(db, "SELECT * FROM jobs WHERE id=:id", {"id": job_id})
    if not row or row.get("stop_requested") or row.get("status") == "paused":
        return {"status": "stopped", "reason": "stop_requested"}
    ready, reason = extraction_barrier(row)
    if not ready:
        return {"status": "held", "reason": "extraction_barrier", "detail": reason}
    ensure_serial_schema(db)
    if stage_rows(db, job_id):
        upgraded = upgrade_serial_layout(db, job_id, schema_name=schema_name,force=reprocess)
        if not upgraded:
            return {"status": "held", "reason": "pipeline_upgrade_busy"}
    # Lock the job while seeding/resetting so two API/watchdog calls cannot reorder stages.
    fetchone(db, "SELECT id FROM jobs WHERE id=:id FOR UPDATE", {"id": job_id})
    for seq, (stage, _label, _agent) in enumerate(STAGES, 1):
        pre = seq <= 3
        skipped = (
            int(_obj(row.get("disk_source")).get("files_skipped") or 0)
            if stage == "extraction"
            else 0
        )
        total = (
            int(row.get("files_total") or row.get("files_extracted") or 0)
            if stage == "extraction"
            else 1
            if pre
            else 0
        )
        completed = (
            int(row.get("files_extracted") or 0)
            if stage == "extraction"
            else 1
            if pre
            else 0
        )
        execute(
            db,
            """INSERT INTO pipeline_stage_runs(job_id,stage,sequence_no,status,completed_at,total_items,completed_items,skipped_items,details)
            VALUES (:jid,:stage,:seq,:status,CASE WHEN :pre THEN NOW() ELSE NULL END,:total,:done,:skipped,CAST(:details AS jsonb))
            ON CONFLICT(job_id,stage) DO NOTHING""",
            {
                "jid": job_id,
                "stage": stage,
                "seq": seq,
                "status": "done" if pre else "pending",
                "pre": pre,
                "total": total,
                "done": completed,
                "skipped": skipped,
                "details": json.dumps(
                    {
                        "completed_before_controller": pre,
                        "skip_reason": "Explicit extractor exceptions"
                        if skipped
                        else None,
                    }
                ),
            },
        )
    if retry_failed:
        execute(
            db,
            "UPDATE pipeline_stage_runs SET status='pending',error=NULL,updated_at=NOW() WHERE job_id=:jid AND status='failed'",
            {"jid": job_id},
        )
    persist_snapshot(db, job_id)
    db.commit()
    return dispatch_current_stage(db, job_id, schema_name=schema_name)


def queue_for_stage(stage: str) -> str:
    from app.forensic_common.pipeline_routing import parse_queue
    from app.service_identity import (
        current_service,
        is_mobile_service,
        mobile_queue_prefix,
    )

    if stage in {"ocr", "media_review"}:
        svc = current_service()
        if is_mobile_service(svc) and svc != "mobile-extract":
            return f"{mobile_queue_prefix(svc)}-ocr"
        return "ocr"
    return parse_queue()


def dispatch_current_stage(
    db, job_id: str, *, schema_name: str, force: bool = False
) -> dict:
    from app.services.mobile_platform_agents import current_service_owns_job

    if not current_service_owns_job(db, job_id):
        return {"status": "held", "reason": "other_product"}
    job = fetchone(
        db,
        "SELECT id,status,stop_requested FROM jobs WHERE id=:id FOR UPDATE",
        {"id": job_id},
    )
    if not job or job.get("stop_requested") or job.get("status") == "paused":
        db.commit()
        return {"status": "paused", "reason": "stop_requested"}
    rows = stage_rows(db, job_id)
    active = first_open_stage(rows)
    if active is None:
        persist_snapshot(db, job_id)
        db.commit()
        return {"status": "ready" if rows else "held"}
    status = active["status"]
    if status == "failed":
        db.commit()
        return {
            "status": "failed",
            "stage": active["stage"],
            "error": active.get("error"),
        }
    if status in {"running", "queued"} and not force:
        db.commit()
        return {"status": status, "stage": active["stage"]}
    tid = str(uuid.uuid4())
    execute(
        db,
        """UPDATE pipeline_stage_runs SET status='queued',task_id=:tid,updated_at=NOW()
        WHERE id=:id""",
        {"id": active["id"], "tid": tid},
    )
    execute(
        db,
        "UPDATE jobs SET status='indexing',error=NULL,updated_at=NOW() WHERE id=:id AND stop_requested=FALSE",
        {"id": job_id},
    )
    persist_snapshot(db, job_id)
    db.commit()
    try:
        from app.tasks import forensic_serial_stage_task

        forensic_serial_stage_task.apply_async(
            args=(schema_name, job_id, active["stage"]),
            queue=queue_for_stage(active["stage"]),
            task_id=tid,
        )
    except Exception as exc:
        execute(
            db,
            """UPDATE pipeline_stage_runs SET status='waiting',error=:err,updated_at=NOW()
            WHERE id=:id AND status='queued' AND task_id=:tid""",
            {"id": active["id"], "tid": tid, "err": f"Queue unavailable: {exc}"[:1000]},
        )
        persist_snapshot(db, job_id)
        db.commit()
        return {
            "status": "waiting",
            "stage": active["stage"],
            "reason": "queue_unavailable",
        }
    return {"status": "queued", "stage": active["stage"], "task_id": tid}


@contextmanager
def pipeline_execution_lock(db, schema_name: str, job_id: str):
    from sqlalchemy import text

    digest = hashlib.sha256(f"serial:{schema_name}:{job_id}".encode()).digest()
    params = {
        "a": int.from_bytes(digest[:4], "big", signed=True),
        "b": int.from_bytes(digest[4:8], "big", signed=True),
    }
    # Keep the SAME physical connection until unlock; ORM commits may recycle theirs.
    with (
        db.get_bind().connect().execution_options(isolation_level="AUTOCOMMIT") as conn
    ):
        got = bool(
            conn.execute(text("SELECT pg_try_advisory_lock(:a,:b)"), params).scalar()
        )
        try:
            yield got
        finally:
            if got:
                conn.execute(text("SELECT pg_advisory_unlock(:a,:b)"), params)


@contextmanager
def stage_heartbeat(schema_name: str, job_id: str, stage_id: str, task_id: str):
    stop = threading.Event()

    def pulse():
        from app.db.session import firm_session

        while not stop.wait(20):
            try:
                with firm_session(schema_name) as db:
                    execute(
                        db,
                        """UPDATE pipeline_stage_runs SET heartbeat_at=NOW(),updated_at=NOW()
                        WHERE id=:id AND task_id=:tid AND status='running'""",
                        {"id": stage_id, "tid": task_id},
                    )
                    db.commit()
                    persist_snapshot(db, job_id)
            except Exception:
                log.exception("Serial stage heartbeat failed job=%s", job_id)

    thread = threading.Thread(target=pulse, name="forensic-heartbeat", daemon=True)
    thread.start()
    try:
        yield
    finally:
        stop.set()
        thread.join(timeout=5)


def run_serial_stage(
    schema_name: str, job_id: str, stage: str, *, task_id: str | None = None
) -> dict:
    if stage not in {name for name, _, _ in STAGES}:
        return {"status": "held", "reason": "obsolete_stage", "stage": stage}
    from app.db.session import firm_session
    from app.services.disk_build_log import write_disk_log
    from app.services.forensic_serial_policy import serial_enabled
    from app.services.forensic_serial_stages import (
        validate_stage_barrier,
    )
    from app.services.mobile_platform_agents import current_service_owns_job

    if not serial_enabled():
        return {"status": "held", "reason": "other_product", "stage": stage}
    with firm_session(schema_name) as db:
        if not current_service_owns_job(db, job_id):
            return {"status": "held", "reason": "other_product", "stage": stage}
        with pipeline_execution_lock(db, schema_name, job_id) as acquired:
            if not acquired:
                return {"status": "busy", "stage": stage}
            rows = stage_rows(db, job_id)
            active = first_open_stage(rows)
            if not active or active["stage"] != stage or active["status"] == "failed":
                return {"status": "held", "reason": "out_of_order", "stage": stage}
            if task_id and active.get("task_id") and task_id != active["task_id"]:
                return {
                    "status": "held",
                    "reason": "superseded_delivery",
                    "stage": stage,
                }
            job = fetchone(db, "SELECT * FROM jobs WHERE id=:id", {"id": job_id})
            ready, reason = extraction_barrier(job)
            if not ready or job.get("stop_requested") or job.get("status") == "paused":
                execute(
                    db,
                    "UPDATE pipeline_stage_runs SET status='waiting',error=:err,updated_at=NOW() WHERE id=:id",
                    {
                        "id": active["id"],
                        "err": reason if not ready else "Paused by user",
                    },
                )
                persist_snapshot(db, job_id)
                return {"status": "waiting", "reason": reason}
            tid = task_id or active.get("task_id") or str(uuid.uuid4())
            execute(
                db,
                """UPDATE pipeline_stage_runs SET status='running',attempt=attempt+1,task_id=:tid,
                started_at=COALESCE(started_at,NOW()),heartbeat_at=NOW(),progress_at=NOW(),
                cancel_requested_at=NULL,operation=NULL,operation_deadline=NULL,updated_at=NOW(),error=NULL WHERE id=:id""",
                {"id": active["id"], "tid": tid},
            )
            persist_snapshot(db, job_id)
            write_disk_log(db, job_id, f"Serial stage started: {stage}", stage=stage)
            # A restart after a progressAgent interrupt is recovery, not a live fault.
            execute(
                db,
                """UPDATE disk_build_logs SET level='info'
                WHERE job_id=:jid AND stage=:stage AND level='warning'
                AND message LIKE 'Serial stage waiting:%interrupted by progressAgent%'""",
                {"jid": job_id, "stage": stage},
            )
            db.commit()
            try:
                with (
                    stage_context(stage),
                    stage_heartbeat(schema_name, job_id, str(active["id"]), tid),
                ):
                    from app.services.forensic_stage_worker import execute_isolated_stage
                    result = execute_isolated_stage(
                        db,
                        job_id,
                        stage,
                        schema_name=schema_name,
                        stage_run_id=str(active["id"]),
                    )
                    # A user stop during the handler must not advance the stage.
                    job = fetchone(
                        db,
                        "SELECT stop_requested,status FROM jobs WHERE id=:id",
                        {"id": job_id},
                    )
                    if job.get("stop_requested") or job.get("status") == "paused":
                        raise StageWaiting("Paused by user or thermal protection")
                    validate_stage_barrier(
                        db, job_id, stage, result, stage_run_id=str(active["id"])
                    )
                execute(
                    db,
                    """UPDATE pipeline_stage_runs SET status=:status,completed_at=NOW(),heartbeat_at=NOW(),
                    updated_at=NOW(),details=CAST(:result AS jsonb),error=NULL,
                    total_items=:total,completed_items=:done,failed_items=:failed,skipped_items=:skipped
                    WHERE id=:id AND task_id=:tid""",
                    {
                        "id": active["id"],
                        "tid": tid,
                        "status": "skipped"
                        if result.get("status") == "skipped"
                        else "done",
                        "result": json.dumps(result, default=str),
                        "total": int(result.get("total") or 0),
                        "done": int(result.get("completed") or 0),
                        "failed": int(result.get("failed") or 0),
                        "skipped": int(result.get("skipped") or 0),
                    },
                )
                write_disk_log(
                    db,
                    job_id,
                    f"Serial stage complete: {stage}",
                    stage=stage,
                    metadata=result,
                )
                if stage == "validation":
                    execute(
                        db,
                        "UPDATE jobs SET status='ready',progress_pct=100,error=NULL,updated_at=NOW() WHERE id=:id",
                        {"id": job_id},
                    )
                else:
                    # Legacy handlers may call the job 'parsed'/'indexed'/'ready'. The
                    # control table, not that milestone, owns overall completion.
                    execute(
                        db,
                        "UPDATE jobs SET status='indexing',updated_at=NOW() WHERE id=:id",
                        {"id": job_id},
                    )
                persist_snapshot(db, job_id)
                db.commit()
            except Exception as exc:
                db.rollback()
                from app.services.db_resilience import is_transient_db_error

                resumable = (
                    isinstance(exc, StageWaiting)
                    or is_transient_db_error(exc)
                    or type(exc).__name__
                    in {
                        "GpuHeavySlotTimeout",
                        "GpuThermalAbort",
                        "ResourceSemaphoreTimeout",
                    }
                )
                status = "waiting" if resumable else "failed"
                execute(
                    db,
                    """UPDATE pipeline_stage_runs SET status=:st,error=:err,heartbeat_at=NOW(),updated_at=NOW()
                    WHERE id=:id AND task_id=:tid""",
                    {
                        "id": active["id"],
                        "tid": tid,
                        "st": status,
                        "err": str(exc)[:2000],
                    },
                )
                execute(
                    db,
                    """UPDATE jobs SET status=CASE WHEN stop_requested OR status='paused' THEN 'paused' ELSE :st END,
                    error=:err,updated_at=NOW() WHERE id=:id""",
                    {
                        "id": job_id,
                        "st": "indexing" if resumable else "failed",
                        "err": str(exc)[:500],
                    },
                )
                write_disk_log(
                    db,
                    job_id,
                    f"Serial stage {status}: {stage} — {exc}",
                    stage=stage,
                    level="warning" if resumable else "error",
                )
                persist_snapshot(db, job_id)
                db.commit()
                return {"status": status, "stage": stage, "error": str(exc)[:2000]}
        # Release the execution lock before publishing the next stage.
        return dispatch_current_stage(db, job_id, schema_name=schema_name)


def watchdog_serial_pipeline(db, job_id: str, *, schema_name: str) -> dict | None:
    """Compatibility entry point; progressAgent owns every recovery decision."""
    from app.services.progress_agent import ensure_progress_schema, monitor_job
    ensure_progress_schema(db)
    return monitor_job(db, job_id, schema_name=schema_name)
