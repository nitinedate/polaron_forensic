"""Segment readiness and disk build orchestration."""

from __future__ import annotations

from app.services.forensic_serial_policy import serial_enabled

import json
import logging
import re
from pathlib import Path

from sqlalchemy.orm import Session

from app.db.sql_helpers import execute, fetchall, fetchone
from app.services.disk_build_log import disk_log_heartbeat, make_session_progress, write_disk_log
from app.services.mobile_segments import mobile_segment_key
from app.services.virtual_disk import open_virtual_disk

log = logging.getLogger("disk")

SEGMENT_RE = re.compile(
    r"^(?P<base>.+)\.(?P<part>\d+)(?P<ext>\.(?:E\d{2}|e\d{2}|001|002|003|004|005|006|007|008|009|dd|raw|aff|aff4|vmdk|vhdx|pas))$",
    re.I,
)


def segment_key(name: str) -> tuple[str, int, str] | None:
    mobile = mobile_segment_key(name)
    if mobile:
        return mobile
    m = SEGMENT_RE.match(name)
    if m:
        ext = m.group("ext").lower()
        base = m.group("base")
        part = int(m.group("part"))
        if ext.startswith(".e") and len(ext) == 4:
            return f"{base}.ewf", part, "ewf"
        return f"{base}{ext}", part, ext.lstrip(".")
    ewf = re.match(r"^(?P<base>.+)\.(?P<seg>E\d{2})$", name, re.I)
    if ewf:
        part = int(ewf.group("seg")[1:])
        base = ewf.group("base")
        return f"{base}.ewf", part, "ewf"
    pas_suffix = re.match(r"^(?P<base>.+)\.pas(?P<part>\d+)$", name, re.I)
    if pas_suffix:
        base = pas_suffix.group("base")
        part = int(pas_suffix.group("part"))
        return f"{base}.pas", part, "pas"
    return None


def is_mobile_format(fmt: str) -> bool:
    return fmt.lower() in ("pas", "ufd", "ufdx", "zip", "mobile")


def segment_readiness(files: list[dict]) -> dict:
    sets: dict[str, dict] = {}
    for f in files:
        name = f.get("original_name") or ""
        if f.get("status") not in (None, "registered", "assembled", "received"):
            continue
        sk = segment_key(name)
        if sk:
            key, part, fmt = sk
            if key not in sets:
                sets[key] = {"base_name": key.rsplit(".", 1)[0], "format": fmt, "present": set(), "parts": []}
            sets[key]["present"].add(part)
            sets[key]["parts"].append(part)
        else:
            key = name or str(f.get("host_path") or f.get("id") or "source")
            sets[key] = {
                "base_name": name or "backup",
                "format": Path(name).suffix.lstrip(".") or "backup",
                "present": {1},
                "parts": [1],
                "single": True,
            }

    disk_sets = []
    gaps = []
    for _key, s in sets.items():
        present = sorted(s["present"])
        if s.get("single"):
            disk_sets.append({
                "base_name": s["base_name"],
                "format": s["format"],
                "present_segments": present,
                "missing_segments": [],
                "missing_labels": [],
                "range_label": "1/1",
                "complete": True,
            })
            continue
        expected_max = max(present) if present else 0
        expected_min = min(present) if present else 0
        # Payload shards are 0-indexed (part-00000). A leftover +2 numbering used to
        # leave a phantom gap at part 1 and keep mobile extract awaiting_segments.
        start = expected_min if (s.get("format") == "zip" and expected_min > 1) else 1
        missing = [i for i in range(start, expected_max + 1) if i not in s["present"]]
        complete = len(missing) == 0 and len(present) > 0
        label = f"{min(present) if present else 0}-{max(present) if present else 0}"
        entry = {
            "base_name": s["base_name"],
            "format": s["format"],
            "present_segments": present,
            "missing_segments": missing,
            "missing_labels": [f"{s['base_name']}.{p:03d}" for p in missing],
            "range_label": label,
            "complete": complete,
        }
        disk_sets.append(entry)
        if not complete:
            gaps.append({**entry, "message": f"Missing segments: {missing}"})

    ready = len(gaps) == 0 and len(disk_sets) > 0
    return {
        "ready": ready,
        "has_disk_segments": len(disk_sets) > 0,
        "disk_sets": disk_sets,
        "gaps": gaps,
        "message": None if ready else (gaps[0]["message"] if gaps else "No disk image files registered"),
    }


def build_extracted_image(db: Session, job_id: str, *, schema_name: str) -> dict:
    """Shared low-level image engine used behind domain-specific orchestrators.

    This function owns only the extraction lock and filesystem/image mechanics.
    Product admission (Disk vs Android vs iOS) belongs to the caller so the
    operational backends never execute each other's job contracts.
    """
    from app.services.job_locks import extract_job_lock, extract_task_in_flight

    if extract_task_in_flight(db, job_id):
        write_disk_log(
            db,
            job_id,
            "Extract already running — ignoring duplicate resume (will not remount or re-enumerate)",
            stage="extract",
            level="warning",
        )
        db.commit()
        return {"status": "already_running"}

    with extract_job_lock(job_id) as acquired:
        if not acquired:
            write_disk_log(
                db,
                job_id,
                "Extract lock held — ignoring duplicate resume",
                stage="extract",
                level="warning",
            )
            db.commit()
            return {"status": "already_running"}
        return _build_extracted_image_locked(db, job_id, schema_name=schema_name)


def build_extracted_disk(db: Session, job_id: str, *, schema_name: str) -> dict:
    """Disk-forensics orchestration entrypoint. Mobile jobs are refused here."""
    from app.forensic_common.job_types import is_mobile_job

    if is_mobile_job(db, job_id):
        raise ValueError(
            "Mobile evidence cannot run through the Disk extraction backend; "
            "use the Android or iOS mobile extraction service"
        )
    return build_extracted_image(db, job_id, schema_name=schema_name)


def _extract_already_complete(db, job_id: str) -> bool:
    row = fetchone(
        db,
        """SELECT status, files_total, files_extracted, extracted_disk_uri, extraction_checkpoint
           FROM jobs WHERE id=:id""",
        {"id": job_id},
    )
    if not row:
        return False
    total = int(row.get("files_total") or 0)
    done = int(row.get("files_extracted") or 0)
    # File counts are the source of truth. A leftover checkpoint or a status
    # flipped back to processing must not restart a finished copy.
    return total > 0 and done >= total


def restore_status_if_extract_complete(db, job_id: str) -> str | None:
    """If extract finished but status is still processing, put the job back to indexing."""
    row = fetchone(
        db,
        """SELECT status, files_total, files_extracted FROM jobs WHERE id=:id""",
        {"id": job_id},
    )
    if not row:
        return None
    status = str(row.get("status") or "").lower()
    if status not in ("processing", "building_disk", "extracting"):
        return None
    if not _extract_already_complete(db, job_id):
        return None
    art = fetchone(db, "SELECT count(*) c FROM job_artifacts WHERE job_id=:jid", {"jid": job_id})
    nxt = "indexing" if int((art or {}).get("c") or 0) > 0 else "disk_ready"
    execute(
        db,
        """UPDATE jobs SET status=:st, error=NULL, stop_requested=FALSE, updated_at=NOW()
           WHERE id=:id""",
        {"st": nxt, "id": job_id},
    )
    write_disk_log(
        db,
        job_id,
        f"Extraction Agent: copy already complete — restored status to {nxt}, not resuming",
        stage="extract",
    )
    return nxt


def _build_extracted_image_locked(db: Session, job_id: str, *, schema_name: str) -> dict:
    if _extract_already_complete(db, job_id):
        restored = restore_status_if_extract_complete(db, job_id)
        write_disk_log(
            db,
            job_id,
            "Extract already complete — not remounting or walking the filesystem again"
            + (f"; status restored to {restored}" if restored else ""),
            stage="extract",
        )
        db.commit()
        return {"status": "already_complete"}

    files = fetchall(db, "SELECT * FROM evidence_files WHERE job_id=:job_id ORDER BY original_name", {"job_id": job_id})
    readiness = segment_readiness(files)
    if not readiness["ready"]:
        try:
            from app.forensic_common.job_types import is_mobile_job
            from app.services.host_evidence import load_job_evidence_folder, register_segments

            if is_mobile_job(db, job_id):
                folder = load_job_evidence_folder(db, job_id)
                if folder:
                    write_disk_log(
                        db,
                        job_id,
                        f"No disk image segments — registering payload ZIP shards near {folder}",
                        stage="extract",
                    )
                    db.commit()
                    try:
                        register_segments(
                            db,
                            job_id,
                            path=folder,
                            source_type="mobile",
                            skip_folder_list=True,
                        )
                    except ValueError as exc:
                        write_disk_log(
                            db,
                            job_id,
                            f"Payload ZIP register waiting for sealed exports: {exc}",
                            stage="extract",
                            level="warning",
                        )
                        db.commit()
                    files = fetchall(
                        db,
                        "SELECT * FROM evidence_files WHERE job_id=:job_id ORDER BY original_name",
                        {"job_id": job_id},
                    )
                    readiness = segment_readiness(files)
        except Exception as exc:
            log.warning("mobile payload auto-register failed job=%s: %s", job_id, exc)
    if not readiness["ready"]:
        execute(
            db,
            "UPDATE jobs SET segment_readiness=CAST(:sr AS jsonb), status='awaiting_segments', updated_at=NOW() WHERE id=:job_id",
            {"sr": json.dumps(readiness), "job_id": job_id},
        )
        db.flush()
        return {"status": "awaiting_segments", "readiness": readiness}

    from app.services.job_locks import CpuHeavySlotTimeout, ExtractSlotAlreadyHeld, cpu_heavy_slot

    # V45.5: one liveness thread for the entire build - CPU-lane wait, image open,
    # enumerate, filter, plan, shards, finalize. Bumps jobs.updated_at every 20 s
    # and logs the current step every 90 s, so no stall detector can misfire on a
    # healthy worker and the operator can see which step is slow.
    from app.services.job_liveness import JobLiveness

    _live = JobLiveness(schema_name, job_id, stage="extract", label="Extraction", lock_kind="extract")
    _live.__enter__()
    _live.step("waiting for CPU lane")
    _extract_slot = cpu_heavy_slot("extract", wait_sec=180.0, fail_closed=True, job_id=job_id)
    try:
        _extract_slot.__enter__()
    except ExtractSlotAlreadyHeld:
        _live.__exit__(None, None, None)
        write_disk_log(
            db,
            job_id,
            "Extract already running — ignoring duplicate resume (will not remount or re-enumerate)",
            stage="extract",
            level="warning",
        )
        db.commit()
        return {"status": "already_running"}
    except CpuHeavySlotTimeout as exc:
        _live.__exit__(None, None, None)
        write_disk_log(
            db,
            job_id,
            f"Extract deferred — chassis busy ({exc})",
            stage="extract",
            level="warning",
        )
        db.commit()
        raise
    try:
        _live.step("open virtual disk")
        execute(db, "UPDATE jobs SET status='building_disk', error=NULL, updated_at=NOW() WHERE id=:job_id", {"job_id": job_id})
        db.flush()
        write_disk_log(
            db,
            job_id,
            f"Opening {len(files)} segment(s) and extracting complete filesystem to MinIO",
            stage="virtual_disk",
        )
        db.commit()

        try:
            on_progress = make_session_progress(
                db, job_id, stage="virtual_disk", commit=True, schema_name=schema_name
            )
            with disk_log_heartbeat(
                schema_name,
                job_id,
                "Opening virtual disk image",
                stage="virtual_disk",
                interval_sec=15.0,
            ):
                vd = open_virtual_disk(db, job_id, on_progress=on_progress)
            write_disk_log(
                db,
                job_id,
                f"Virtual disk mounted — {vd.format.upper()} · {len(files)} segment(s) · mode={vd.mode}",
                stage="virtual_disk",
                metadata={"base_name": vd.base_name, "format": vd.format, "mode": vd.mode},
            )
            # Mark mount complete so UI advances Virtual disk → Extraction immediately.
            # Preserve examiner mobile_os / capability metadata seeded at job create.
            from app.services.mobile_os import extract_mobile_meta, load_job_disk_source, merge_mobile_meta_into_disk_source

            prior = load_job_disk_source(
                fetchone(db, "SELECT disk_source FROM jobs WHERE id=:job_id", {"job_id": job_id})
            )
            mount_ds = merge_mobile_meta_into_disk_source(
                {
                    "mounted": True,
                    "base_name": vd.base_name,
                    "format": vd.format,
                    "mode": vd.mode,
                    "segments": len(files),
                },
                extract_mobile_meta(prior),
            )
            execute(
                db,
                """UPDATE jobs SET
                     disk_source=CAST(:ds AS jsonb),
                     progress_pct=GREATEST(COALESCE(progress_pct, 0), 4),
                     updated_at=NOW()
                   WHERE id=:job_id""",
                {
                    "ds": json.dumps(mount_ds),
                    "job_id": job_id,
                },
            )
            write_disk_log(
                db,
                job_id,
                "Virtual disk complete — starting extraction immediately",
                stage="extract",
            )
            db.commit()
        except ValueError as e:
            write_disk_log(db, job_id, f"Failed to open virtual disk: {e}", stage="virtual_disk", level="error")
            db.commit()
            execute(
                db,
                "UPDATE jobs SET status='failed', error=:err, updated_at=NOW() WHERE id=:job_id",
                {"err": str(e)[:500], "job_id": job_id},
            )
            db.flush()
            return {"status": "failed", "error": str(e)}

        from app.services.extracted_disk import build_extracted_disk_to_minio

        try:
            _live.step("extract")
            # Adaptive shared CPU/I/O admission across Disk/Android/iOS products. GPU OCR/RAG has a separate governed lane.
            result = build_extracted_disk_to_minio(db, job_id, vd, schema_name=schema_name)
        except Exception as exc:
            # DB disconnect mid-extract leaves the session in PendingRollbackError —
            # must rollback before any further SQL or the job stays stuck in building_disk.
            from app.services.db_resilience import (
                TransientDatabaseError,
                is_transient_db_error,
                wait_for_database,
            )
            from app.services.job_control import mark_job_paused

            try:
                db.rollback()
            except Exception:
                pass
            if is_transient_db_error(exc):
                log.warning("Extract hit a recoverable database outage job=%s: %s", job_id, exc)
                wait_for_database(timeout_sec=180)
                try:
                    from app.db.session import firm_session

                    with firm_session(schema_name) as fresh:
                        write_disk_log(
                            fresh,
                            job_id,
                            "Database was recovering. Extraction checkpoint is kept and will resume automatically.",
                            stage="extract",
                            level="warning",
                        )
                        mark_job_paused(
                            fresh,
                            job_id,
                            message="Extraction stalled — database was recovering. Automatic resume.",
                        )
                        execute(
                            fresh,
                            "UPDATE jobs SET celery_task_id=NULL, updated_at=NOW() WHERE id=:job_id",
                            {"job_id": job_id},
                        )
                        fresh.commit()
                except Exception:
                    log.exception("Could not persist extract pause after database recovery job=%s", job_id)
                raise TransientDatabaseError(str(exc)[:500]) from exc
            try:
                from app.db.session import apply_firm_search_path

                apply_firm_search_path(db, schema_name)
            except Exception:
                pass
            try:
                write_disk_log(
                    db,
                    job_id,
                    f"Extraction failed: {exc}",
                    stage="extract",
                    level="error",
                )
                execute(
                    db,
                    "UPDATE jobs SET status='failed', error=:err, celery_task_id=NULL, updated_at=NOW() WHERE id=:job_id",
                    {"err": str(exc)[:500], "job_id": job_id},
                )
                db.commit()
            except Exception:
                try:
                    db.rollback()
                except Exception:
                    pass
                log.exception("Failed to persist extract failure for job %s", job_id)
            return {"status": "failed", "error": str(exc)}
        status = result.get("status", "failed")
        settings = __import__("app.config", fromlist=["get_settings"]).get_settings()
        if status == "disk_ready":
            from app.services.mobile_os import extract_mobile_meta, load_job_disk_source, merge_mobile_meta_into_disk_source

            manifest = dict(result.get("manifest") or {})
            prior = load_job_disk_source(
                fetchone(db, "SELECT disk_source FROM jobs WHERE id=:job_id", {"job_id": job_id})
            )
            manifest = merge_mobile_meta_into_disk_source(manifest, extract_mobile_meta(prior))
            if (
                not bool(getattr(settings, "extract_then_process", True)) and not serial_enabled()
                and settings.phase3_stream_during_extract
                and settings.phase3_auto_after_disk
            ):
                manifest["phase3_finalize_queued"] = True
            if manifest.get("mobile_os") or prior.get("mobile_os"):
                write_disk_log(
                    db,
                    job_id,
                    f"Mobile working image ready — OS={manifest.get('mobile_os')} "
                    f"capability={manifest.get('capability_label')} "
                    f"provenance={((manifest.get('collection_summary') or {}).get('provenance') or 'import')}",
                    stage="extract",
                    metadata={
                        "mobile_os": manifest.get("mobile_os"),
                        "capability_label": manifest.get("capability_label"),
                        "import_adapter": manifest.get("import_adapter"),
                    },
                )
            execute(
                db,
                """UPDATE jobs SET segment_readiness=CAST(:sr AS jsonb), status='disk_ready', progress_pct=100,
                   extracted_disk_uri=:uri, disk_source=CAST(:ds AS jsonb),
                   files_total=:total, files_extracted=:extracted, bytes_extracted=:bytes,
                   extraction_checkpoint=NULL, celery_task_id=NULL, stop_requested=FALSE,
                   error=NULL, updated_at=NOW() WHERE id=:job_id""",
                {
                    "sr": json.dumps(readiness),
                    "uri": result.get("extracted_disk_uri"),
                    "ds": json.dumps(manifest),
                    "total": result.get("files_total", 0),
                    "extracted": result.get("files_extracted", 0),
                    "bytes": result.get("bytes_extracted", 0),
                    "job_id": job_id,
                },
            )
            write_disk_log(
                db,
                job_id,
                f"Extracted disk ready — {result.get('files_extracted', 0):,} files "
                f"({result.get('bytes_extracted', 0):,} bytes) in MinIO",
                stage="extract",
                metadata=result,
            )
            from app.services.artifact_selection_catalog import persist_job_axiom_platform

            platform = persist_job_axiom_platform(db, job_id)
            write_disk_log(
                db,
                job_id,
                f"Artifact catalog platform — {platform}",
                stage="extract",
                metadata={"axiom_platform": platform},
            )
            db.commit()
            from app.forensic_common.pipeline_routing import should_continue_after_extract
            from app.service_identity import current_service, is_mobile_service

            mobile_svc = is_mobile_service(current_service())
            if should_continue_after_extract(
                phase3_auto=bool(settings.phase3_auto_after_disk),
                rag_auto=bool(settings.rag_auto_after_disk),
            ):
                from app.tasks import phase3_finalize_task, phase3_pipeline_task, rag_index_task

                use_phase3 = mobile_svc or bool(settings.phase3_auto_after_disk)
                if (
                    not bool(getattr(settings, "extract_then_process", True)) and not serial_enabled()
                    and settings.phase3_stream_during_extract
                    and settings.phase3_auto_after_disk
                    and not mobile_svc
                ):
                    task = phase3_finalize_task
                    phase_label = "Phase 3 finalize (streamed pipeline)"
                else:
                    task = phase3_pipeline_task if use_phase3 else rag_index_task
                    phase_label = "Phase 3 evidence pipeline" if use_phase3 else "GPU RAG indexing"
                # Strict extract-then-process mode starts exactly one post-extract
                # orchestrator. Do not separately queue parse/inventory before
                # materialization: those duplicate tasks made the UI appear to run
                # several phases while extraction was still finishing and stole I/O.
                if not bool(getattr(settings, "extract_then_process", True)) and not serial_enabled():
                    try:
                        from app.tasks import parse_drain_task

                        parse_drain_task.delay(schema_name, job_id)
                        write_disk_log(
                            db,
                            job_id,
                            "Queued background parse on disk worker (streaming mode)",
                            stage="parse",
                        )
                    except Exception as exc:
                        log.warning("Queue parse after extract failed job=%s: %s", job_id, exc)
                    try:
                        from app.services.catalog_artifact_runner import queue_axiom_artifact_inventory

                        queue_axiom_artifact_inventory(db, job_id, schema_name=schema_name)
                    except Exception as exc:
                        log.warning("Queue inventory after extract failed job=%s: %s", job_id, exc)
                write_disk_log(
                    db,
                    job_id,
                    f"Extraction barrier complete — queueing {phase_label}",
                    stage="phase3" if use_phase3 else "rag_index",
                )
                execute(
                    db,
                    "UPDATE jobs SET status='indexing', error=NULL, updated_at=NOW() WHERE id=:job_id",
                    {"job_id": job_id},
                )
                db.commit()
                try:
                    task.delay(schema_name, job_id)
                except Exception as exc:
                    write_disk_log(
                        db,
                        job_id,
                        f"Failed to queue {phase_label}: {exc} — ensure the extract worker and Redis are running",
                        stage="phase3",
                        level="error",
                    )
                    execute(
                        db,
                        "UPDATE jobs SET status='disk_ready', error=:err, updated_at=NOW() WHERE id=:job_id",
                        {"err": f"Pipeline queue failed: {exc}"[:500], "job_id": job_id},
                    )
                    db.commit()
        elif status == "paused":
            execute(
                db,
                "UPDATE jobs SET celery_task_id=NULL, updated_at=NOW() WHERE id=:job_id",
                {"job_id": job_id},
            )
            db.commit()
        else:
            execute(
                db,
                "UPDATE jobs SET status='failed', error=:err, updated_at=NOW() WHERE id=:job_id",
                {"err": (result.get("error") or "disk build failed")[:500], "job_id": job_id},
            )
            write_disk_log(db, job_id, result.get("error") or "Disk build failed", stage="virtual_disk", level="error")
        db.flush()
        return result
    finally:
        try:
            _live.write_summary(db)
        except Exception:
            pass
        _live.__exit__(None, None, None)
        _extract_slot.__exit__(None, None, None)
