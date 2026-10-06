"""Phase 3 evidence pipeline — materialize → parse → OCR → dual RAG → graph."""

from __future__ import annotations

import json
import logging

from app.config import get_settings
from app.db.sql_helpers import execute, fetchone
from app.services.artifact_materialize import materialize_job_artifacts
from app.services.artifact_parse import parse_job_artifacts
from app.services.disk_build_log import write_disk_log
from app.services.dual_rag_index import build_dual_rag_index
from app.services.neo4j_sync import sync_job_graph
from app.services.ocr_gpu import dispatch_ocr_agent
from app.services.pipeline_progress import write_merged_pipeline_progress
from app.services.tar_cache import clear_tar_cache

log = logging.getLogger("phase3_pipeline")


def _build_index_map(db, job_id: str) -> tuple[dict, list]:
    row = fetchone(db, "SELECT disk_source FROM jobs WHERE id=:id", {"id": job_id})
    manifest = row["disk_source"]
    if isinstance(manifest, str):
        manifest = json.loads(manifest)
    from app.services.disk_manifest import build_index_map

    index_map = build_index_map(manifest)
    parts = list(manifest.get("parts") or []) or list(dict.fromkeys(index_map.values()))
    return index_map, parts


def run_phase3_pipeline(db, job_id: str, *, schema_name: str) -> dict:
    from app.services.forensic_serial_policy import serial_enabled

    from app.services.rag_image_evidence import is_image_evidence_job

    if serial_enabled() and not is_image_evidence_job(db, job_id):
        from app.services.forensic_serial_pipeline import start_serial_pipeline

        return start_serial_pipeline(db, job_id, schema_name=schema_name)
    settings = get_settings()
    clear_tar_cache()
    write_disk_log(db, job_id, "Phase 3 pipeline started", stage="phase3")
    write_merged_pipeline_progress(
        db,
        job_id,
        {"phase": "materialize", "completed": 0, "total": 0, "label": "Registering artifacts from extracted evidence"},
        writer="phase3",
        status_sql="status='indexing'",
    )
    db.commit()

    mat = materialize_job_artifacts(db, job_id, schema_name=schema_name)
    if mat.get("status") != "ok":
        return mat

    if not mat.get("skipped"):
        execute(
            db,
            """UPDATE job_artifacts SET parse_status='pending', updated_at=NOW()
               WHERE job_id=:jid AND parse_status='skipped'""",
            {"jid": job_id},
        )
        db.commit()

    index_map, _ = _build_index_map(db, job_id)
    total_artifacts = mat.get("artifacts_total", 0)

    pending = fetchone(
        db,
        "SELECT count(*) c FROM job_artifacts WHERE job_id=:jid AND parse_status='pending'",
        {"jid": job_id},
    )
    parsed_total = 0
    if pending and int(pending["c"]) > 0:
        from app.services.artifact_parse import drain_pending_parse

        drain = drain_pending_parse(
            db, job_id, index_map=index_map, requeue_no_parser=True, update_job_status=True,
        )
        parsed_total = int(drain.get("parsed") or 0)
        write_disk_log(
            db,
            job_id,
            f"Full parse drain — {parsed_total:,} parsed across {drain.get('rounds', 0)} rounds",
            stage="parse",
            metadata=drain,
        )
        db.commit()

    if settings.ocr_enabled:
        # Disk-build has no CUDA. Inline run_ocr_for_job left scans pending forever
        # with "CUDA is unavailable on this worker". Hand GLM to worker-ocr-gpu.
        workers = dispatch_ocr_agent(schema_name, job_id)
        write_disk_log(
            db,
            job_id,
            f"OCR dispatched to {workers} worker(s) — GLM on CUDA, text-layer on CPU",
            stage="ocr",
            metadata={"ocr_workers": workers},
        )
        db.commit()

    rag = build_dual_rag_index(db, job_id, schema_name=schema_name, index_map=index_map)
    graph = sync_job_graph(db, job_id, schema_name=schema_name)
    clear_tar_cache()

    write_disk_log(
        db,
        job_id,
        f"Phase 3 complete — {mat.get('artifacts_total', 0):,} artifacts, {rag.get('chunks_total', 0):,} chunks",
        stage="phase3",
        metadata={"materialize": mat, "rag": rag, "graph": graph, "parsed": parsed_total},
    )
    db.commit()
    return {
        "status": "indexed",
        "materialize": mat,
        "parsed": parsed_total,
        "rag": rag,
        "graph": graph,
    }
