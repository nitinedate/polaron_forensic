"""Mobile native parse/recovery adapters with four claimed evidence bundles."""

from __future__ import annotations

import hashlib
import json
import threading
import time

from app.db.session import firm_session
from app.db.sql_helpers import execute, fetchall, fetchone
from app.services.forensic_serial_policy import bounded_map, stage_context
from app.services.mobile_forensic.discovery import inventory_from_job_artifacts
from app.services.mobile_forensic.models import InventoryItem
from app.services.mobile_forensic.plugins import ParseContext, get_plugin_registry
from app.services.mobile_forensic.storage import (
    _dumps,
    ensure_mobile_case_schema,
    persist_source_manifest,
    start_analysis_run,
    update_analysis_run,
)

SIDECARS = ("-wal", "-shm", "-journal")
_PROGRESS_LOCK = threading.Lock()
_PROGRESS_AT = 0.0


def _publish_work_progress(db, job_id, stage, stage_run_id, *, force=False):
    """Record bundle progress on the stage row.

    Recovery used to finish thousands of files without moving progress_at.
    progressAgent then treated the stage as stalled, cancelled it, and the
    card fell back to waiting at 0 even though the finished bundles remained.
    """
    global _PROGRESS_AT
    now = time.monotonic()
    with _PROGRESS_LOCK:
        if not force and now - _PROGRESS_AT < 5:
            return
        _PROGRESS_AT = now
    counts = fetchone(
        db,
        """SELECT count(*) AS total,count(*) FILTER (WHERE status='done') AS done,
        count(*) FILTER (WHERE status='failed') AS failed
        FROM pipeline_work_items WHERE stage_run_id=:sid""",
        {"sid": stage_run_id},
    )
    if not counts or not int(counts["total"] or 0):
        return
    from app.services.forensic_serial_stages import report_progress

    labels = {
        "parse": "Native forensic parsing",
        "recovery": "Deleted / recovery analysis",
    }
    report_progress(
        db,
        job_id,
        stage,
        total=int(counts["total"]),
        completed=int(counts["done"] or 0),
        failed=int(counts["failed"] or 0),
        label=labels.get(stage, stage),
    )


def _persist_inventory_bulk(db, job_id, items):
    from psycopg2.extras import execute_values

    values = [
        (
            job_id,
            it.path,
            it.size,
            it.extension,
            it.mime_hint,
            it.sha256,
            it.status,
            it.parser,
            it.error,
            _dumps(it.meta or {}),
        )
        for it in items
    ]
    if not values:
        return 0
    with db.connection().connection.cursor() as cur:
        execute_values(
            cur,
            """INSERT INTO mobile_inventory_items
            (job_id,path,size_bytes,extension,mime_hint,sha256,status,parser,error,meta) VALUES %s
            ON CONFLICT(job_id,path) DO UPDATE SET size_bytes=EXCLUDED.size_bytes,
                extension=EXCLUDED.extension,mime_hint=EXCLUDED.mime_hint,
                sha256=COALESCE(EXCLUDED.sha256,mobile_inventory_items.sha256),
                status=CASE WHEN EXCLUDED.status='discovered' THEN mobile_inventory_items.status ELSE EXCLUDED.status END,
                parser=COALESCE(EXCLUDED.parser,mobile_inventory_items.parser),
                error=CASE WHEN EXCLUDED.status='discovered' THEN mobile_inventory_items.error ELSE EXCLUDED.error END,
                meta=mobile_inventory_items.meta || EXCLUDED.meta,updated_at=NOW()""",
            values,
            template="(%s,%s,%s,%s,%s,%s,%s,%s,%s,%s::jsonb)",
            page_size=500,
        )
    return len(values)


def _persist_artifacts_bulk(db, job_id, artifacts):
    from psycopg2.extras import execute_values

    # Multiple parsers can emit the same deterministic ID within a checkpoint.
    unique = {art.artifact_id: art for art in artifacts}
    values = []
    for art in unique.values():
        from app.services.forensic_priority_evidence import add_record_links
        add_record_links(art)
        forensic = art.forensic or {}
        values.append(
            (
                art.artifact_id,
                job_id,
                art.artifact_type,
                art.source_domain,
                art.timestamp_utc,
                forensic.get("state") or "allocated",
                forensic.get("ui_label"),
                _dumps(art.data or {}),
                _dumps(forensic),
                forensic.get("examiner_status") or "pending_review",
            )
        )
    if not values:
        return 0
    with db.connection().connection.cursor() as cur:
        execute_values(
            cur,
            """INSERT INTO mobile_normalized_artifacts
            (artifact_id,job_id,artifact_type,source_domain,timestamp_utc,state,ui_label,data,forensic,examiner_status)
            VALUES %s ON CONFLICT(artifact_id) DO UPDATE SET artifact_type=EXCLUDED.artifact_type,
                source_domain=EXCLUDED.source_domain,timestamp_utc=EXCLUDED.timestamp_utc,
                state=EXCLUDED.state,ui_label=EXCLUDED.ui_label,data=EXCLUDED.data,
                forensic=EXCLUDED.forensic,updated_at=NOW()""",
            values,
            template="(%s,%s,%s,%s,%s::timestamptz,%s,%s,%s::jsonb,%s::jsonb,%s)",
            page_size=500,
        )
    return len(values)


def _analysis_run(db, job_id, stage, platform):
    row = fetchone(
        db,
        """SELECT run_id FROM mobile_analysis_runs WHERE job_id=:jid
        AND details->>'serial_pipeline'='true' ORDER BY started_at DESC LIMIT 1""",
        {"jid": job_id},
    )
    run_id = row["run_id"] if row else start_analysis_run(db, job_id, platform=platform)
    update_analysis_run(
        db, run_id, phase=stage, status="running", details={"serial_pipeline": True}
    )
    return run_id


def complete_mobile_analysis(db, job_id, validation):
    row = fetchone(
        db,
        """SELECT run_id FROM mobile_analysis_runs WHERE job_id=:jid
        AND details->>'serial_pipeline'='true' ORDER BY started_at DESC LIMIT 1""",
        {"jid": job_id},
    )
    if row:
        update_analysis_run(
            db,
            row["run_id"],
            status="completed",
            phase="complete",
            details={"serial_pipeline": True, "validation": validation},
        )


def evidence_bundles(items):
    """Keep a database and all sidecars in the same worker, including extensionless DBs."""
    groups = {}
    for item in items:
        key = item.path.replace("\\", "/")
        lower = key.lower()
        for suffix in SIDECARS:
            if lower.endswith(suffix):
                key = key[: -len(suffix)]
                break
        groups.setdefault(key, []).append(item)
    return [
        sorted(group, key=lambda item: (item.path.endswith(SIDECARS), item.path))
        for group in groups.values()
    ]


def _context(db, job_id, ds, *, references=None, evidence_paths=(), whatsapp_key_candidates=None):
    from app.services.artifact_selection_catalog import resolve_job_axiom_platform
    from app.services.mobile_forensic.integrity import load_intake_keys_from_disk_source
    from app.services.mobile_forensic.parsers._sqlite_util import SqliteEvidenceBytes
    from app.services.mobile_forensic.sqlite_counts import (
        _read_artifact_bytes,
        discover_whatsapp_keys,
    )

    keys = load_intake_keys_from_disk_source(ds)
    if whatsapp_key_candidates is None:
        whatsapp_key_candidates = discover_whatsapp_keys(db, job_id)
    acquired_paths = set(evidence_paths)
    read_errors = set()

    def read_one(path, max_bytes):
        try:
            data = _read_artifact_bytes(db, job_id, path, max_bytes=max_bytes)
        except Exception:
            read_errors.add(path)
            raise
        if data is None and path in acquired_paths:
            read_errors.add(path)
        return data

    def read(path, max_bytes=120_000_000):
        data = read_one(path, max_bytes)
        if data and data.startswith(b"SQLite format 3\x00"):
            companions = {}
            for suffix in SIDECARS:
                if path + suffix not in acquired_paths:
                    continue
                companion = read_one(path + suffix, max_bytes)
                if companion:
                    companions[suffix] = companion
            return SqliteEvidenceBytes(data, companions)
        return data

    return ParseContext(
        job_id=job_id,
        platform=str(resolve_job_axiom_platform(db, job_id) or "Android"),
        source_id=(ds.get("evidence_manifest") or {}).get("source_id"),
        whatsapp_key_hex=keys.get("whatsapp_key_hex"),
        whatsapp_legacy_account=keys.get("whatsapp_legacy_account"),
        whatsapp_key_candidates=whatsapp_key_candidates,
        signal_db_key_hex=keys.get("signal_db_key_hex"),
        ios_backup_password=keys.get("ios_backup_password"),
        read_bytes=read,
        db=db,
        extra={
            "referenced_media_names": set(references or []),
            "read_errors": read_errors,
            "evidence_paths": acquired_paths,
        },
    )


def _seed_work(db, stage_run_id, bundles):
    from psycopg2.extras import execute_values

    values = []
    for bundle in bundles:
        payload = [
            {
                "path": it.path,
                "size": it.size,
                "extension": it.extension,
                "mime_hint": it.mime_hint,
                "sha256": it.sha256,
                "meta": it.meta,
            }
            for it in bundle
        ]
        key = hashlib.sha256(bundle[0].path.encode()).hexdigest()
        values.append((stage_run_id, key, json.dumps(payload)))
        if len(values) >= 1000:
            with db.connection().connection.cursor() as cur:
                execute_values(
                    cur,
                    """INSERT INTO pipeline_work_items(stage_run_id,partition_key,payload)
                    VALUES %s ON CONFLICT(stage_run_id,partition_key) DO NOTHING""",
                    values,
                    template="(%s,%s,%s::jsonb)",
                    page_size=500,
                )
            db.commit()
            values.clear()
    if values:
        with db.connection().connection.cursor() as cur:
            execute_values(
                cur,
                """INSERT INTO pipeline_work_items(stage_run_id,partition_key,payload)
                VALUES %s ON CONFLICT(stage_run_id,partition_key) DO NOTHING""",
                values,
                template="(%s,%s,%s::jsonb)",
                page_size=500,
            )
    # A killed stage may have left claims. The caller holds the job execution lock.
    execute(
        db,
        "UPDATE pipeline_work_items SET status='pending' WHERE stage_run_id=:sid AND status='running'",
        {"sid": stage_run_id},
    )
    db.commit()


def run_mobile_stage(db, job_id, stage, *, schema_name, stage_run_id):
    ensure_mobile_case_schema(db)
    db.commit()  # Finish DDL before opening independent worker Sessions.
    items = inventory_from_job_artifacts(db, job_id)
    from app.services.artifact_selection_catalog import resolve_job_axiom_platform

    run_id = _analysis_run(
        db, job_id, stage, str(resolve_job_axiom_platform(db, job_id) or "Android")
    )
    if stage == "normalize":
        from app.services.mobile_forensic.correlation import correlate_artifacts_db
        from app.services.mobile_forensic.coverage import persist_coverage_snapshot
        from app.services.mobile_forensic.storage import artifact_counts_by_domain

        relationships = correlate_artifacts_db(db, job_id)
        counts = artifact_counts_by_domain(db, job_id)
        states = {
            r["path"]: r
            for r in fetchall(
                db,
                "SELECT path,status,parser,error FROM mobile_inventory_items WHERE job_id=:jid",
                {"jid": job_id},
            )
        }
        for item in items:
            if item.path in states:
                item.status = states[item.path]["status"]
                item.parser = states[item.path]["parser"]
                item.error = states[item.path]["error"]
        persist_coverage_snapshot(db, job_id, items, counts)
        from app.services.forensic_priority_evidence import mobile_priority_coverage
        mobile_priority_coverage(db, job_id)
        update_analysis_run(
            db,
            run_id,
            inventory_total=len(items),
            files_processed=sum(
                it.status in {"parsed", "unsupported", "error"} for it in items
            ),
            unsupported_files=sum(it.status == "unsupported" for it in items),
            parse_errors=sum(it.status == "error" for it in items),
            artifacts_written=int(counts.get("total") or 0),
        )
        db.commit()
        return {
            "status": "ok",
            "relationships": relationships,
            "counts": counts,
            "run_id": run_id,
        }
    row = fetchone(db, "SELECT disk_source FROM jobs WHERE id=:jid", {"jid": job_id})
    ds = row.get("disk_source") or {}
    if isinstance(ds, str):
        ds = json.loads(ds)
    if stage == "parse" and isinstance(ds.get("evidence_manifest"), dict):
        persist_source_manifest(db, job_id, ds["evidence_manifest"])
    # Prepare/discover key once, not once for every database.
    seed_context = _context(db, job_id, ds)
    references = []
    if stage == "recovery":
        refs = fetchall(
            db,
            """SELECT DISTINCT lower(regexp_replace(value,'^.*[\\/]','')) AS name
            FROM mobile_normalized_artifacts m
            CROSS JOIN LATERAL jsonb_each_text(m.data) e(key,value)
            WHERE m.job_id=:jid AND e.key IN ('media_name','media_path','attachment','attachment_path')""",
            {"jid": job_id},
        )
        references = [row["name"] for row in refs if row["name"]]
    if stage == "parse":
        for start in range(0, len(items), 1000):
            _persist_inventory_bulk(db, job_id, items[start : start + 1000])
            db.commit()
    bundles = evidence_bundles(items)
    _seed_work(db, stage_run_id, bundles)
    db.commit()
    _publish_work_progress(db, job_id, stage, stage_run_id, force=True)
    from app.services.forensic_priority_evidence import PRIORITY_ORDER_SQL
    cancelled = threading.Event()

    def worker(slot):
        written = errors = processed = unsupported = 0
        with firm_session(schema_name) as wdb, stage_context(stage):
            context = _context(
                wdb,
                job_id,
                ds,
                references=references,
                evidence_paths=(item.path for item in items),
                whatsapp_key_candidates=seed_context.whatsapp_key_candidates,
            )
            registry = get_plugin_registry()
            while not cancelled.is_set():
                from app.services.job_control import pipeline_should_stop

                if pipeline_should_stop(wdb, job_id):
                    cancelled.set()
                    break
                work = fetchone(
                    wdb,
                    f"""WITH candidate AS (
                    SELECT id FROM pipeline_work_items WHERE stage_run_id=:sid AND status='pending'
                    ORDER BY {PRIORITY_ORDER_SQL} LIMIT 1 FOR UPDATE SKIP LOCKED)
                    UPDATE pipeline_work_items w SET status='running',attempt=attempt+1,
                        worker_id=:worker,started_at=NOW(),error=NULL
                    FROM candidate c WHERE w.id=c.id RETURNING w.id,w.payload""",
                    {"sid": stage_run_id, "worker": f"slot-{slot}"},
                )
                wdb.commit()
                if not work:
                    break
                payload = work["payload"]
                if isinstance(payload, str):
                    payload = json.loads(payload)
                bundle = [InventoryItem(**row) for row in payload]
                buffer = []
                failures = []
                context.extra["read_errors"].clear()
                try:
                    for item in bundle:
                        if stage == "recovery" and item is not bundle[0]:
                            processed += 1
                            continue
                        parsers = (
                            registry.route(item, context)
                            if stage == "parse"
                            else registry.recovery_analyzers
                        )
                        item_written = 0
                        item_failures = []
                        for parser in parsers:
                            try:
                                output = (
                                    parser.parse(item, context)
                                    if stage == "parse"
                                    else parser.analyze(
                                        [item] if len(bundle) == 1 else bundle,
                                        [],
                                        context,
                                    )
                                )
                                # A recovery analyzer receives the WHOLE bundle once.
                                for artifact in output:
                                    companions = [
                                        {
                                            "path": it.path,
                                            "sha256": it.sha256,
                                            "size_bytes": it.size,
                                        }
                                        for it in bundle
                                        if it.path.lower().endswith(SIDECARS)
                                    ]
                                    if (
                                        companions
                                        and artifact.forensic.get("source_path")
                                        == bundle[0].path
                                    ):
                                        artifact.forensic["source_companions"] = (
                                            companions
                                        )
                                    buffer.append(artifact)
                                    item_written += 1
                                    if len(buffer) >= 500:
                                        written += _persist_artifacts_bulk(
                                            wdb, job_id, buffer
                                        )
                                        buffer.clear()
                                        wdb.commit()
                                        from app.services.progress_agent import note_operation
                                        note_operation(wdb,job_id,stage,'Parsed 500 source records',advanced=True)
                                        if pipeline_should_stop(wdb, job_id):
                                            cancelled.set()
                                            raise RuntimeError("Paused by user")
                            except Exception as exc:
                                if cancelled.is_set():
                                    raise
                                item_failures.append(
                                    f"{item.path}: {parser.name}: {exc}"[:1000]
                                )
                                errors += 1
                        if context.extra["read_errors"]:
                            item_failures.extend(
                                f"Acquired evidence could not be read: {path}"
                                for path in sorted(context.extra["read_errors"])
                            )
                            errors += len(context.extra["read_errors"])
                            context.extra["read_errors"].clear()
                        failures.extend(item_failures)
                        if stage == "parse":
                            item.status = (
                                "error"
                                if item_failures
                                else "parsed"
                                if item_written
                                else "unsupported"
                            )
                            item.parser = ",".join(p.name for p in parsers)
                            item.error = (
                                "; ".join(item_failures[-4:])
                                if item.status == "error"
                                else None
                            )
                            if item.status == "unsupported":
                                unsupported += 1
                            _persist_inventory_bulk(wdb, job_id, [item])
                        processed += 1
                    written += _persist_artifacts_bulk(wdb, job_id, buffer)
                    execute(
                        wdb,
                        """UPDATE pipeline_work_items SET status=:status,error=:err,completed_at=NOW()
                        WHERE id=:id""",
                        {
                            "id": work["id"],
                            "status": "failed" if failures else "done",
                            "err": "; ".join(failures)[:4000] if failures else None,
                        },
                    )
                    wdb.commit()
                    _publish_work_progress(wdb, job_id, stage, stage_run_id)
                    context.clear_byte_cache()
                except Exception as exc:
                    wdb.rollback()
                    # Infrastructure/persistence failures stop the barrier. Evidence
                    # parser failures above remain recorded exceptions per bundle.
                    execute(
                        wdb,
                        "UPDATE pipeline_work_items SET status='pending',error=:err WHERE id=:id",
                        {"id": work["id"], "err": str(exc)[:2000]},
                    )
                    wdb.commit()
                    cancelled.set()
                    raise
        return {
            "written": written,
            "errors": errors,
            "processed": processed,
            "unsupported": unsupported,
        }

    totals = {"written": 0, "errors": 0, "processed": 0, "unsupported": 0}
    for result in bounded_map(worker, range(1, 5)):
        for key in totals:
            totals[key] += result[key]
    if cancelled.is_set():
        from app.services.forensic_serial_pipeline import StageWaiting

        raise StageWaiting("Mobile stage paused; unfinished bundles remain pending")
    if stage == "recovery":
        from app.services.mobile_forensic.deleted_pipeline import (
            ensure_mobile_deleted_pipeline,
        )

        # Use the existing deleted-data bridge for the report/catalog consumers;
        # native recovery artifacts above retain full forensic provenance.
        ensure_mobile_deleted_pipeline(db, job_id, carve_sqlite=True)
        db.commit()
    work_counts = fetchone(
        db,
        """SELECT count(*) AS total,count(*) FILTER(WHERE status='done') AS completed,
        count(*) FILTER(WHERE status='failed') AS failed FROM pipeline_work_items WHERE stage_run_id=:sid""",
        {"sid": stage_run_id},
    )
    update_analysis_run(
        db,
        run_id,
        inventory_total=len(items),
        **(
            {"recovered_written": totals["written"]}
            if stage == "recovery"
            else {
                "files_processed": totals["processed"],
                "artifacts_written": totals["written"],
                "parse_errors": totals["errors"],
                "unsupported_files": totals["unsupported"],
            }
        ),
    )
    db.commit()
    return {
        "status": "ok",
        **dict(work_counts),
        **totals,
        "inventory_total": len(items),
        "parallelism": 4,
        "run_id": run_id,
    }
