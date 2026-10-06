"""Serial adapters for the existing evidence engines, with explicit barriers."""

from __future__ import annotations

import json
from contextlib import ExitStack

from app.db.sql_helpers import execute, fetchall, fetchone
from app.services.forensic_serial_pipeline import StageWaiting
from app.services.forensic_serial_policy import CHUNK_POLICY, bounded_map

NIL_ID = "00000000-0000-0000-0000-000000000000"


def report_progress(
    db, job_id, stage, *, total, completed, failed=0, skipped=0, label=None
):
    execute(
        db,
        """UPDATE pipeline_stage_runs SET progress_at=CASE WHEN
        (total_items,completed_items,failed_items,skipped_items) IS DISTINCT FROM
        (CAST(:total AS bigint),CAST(:done AS bigint),CAST(:failed AS bigint),CAST(:skipped AS bigint))
        THEN NOW() ELSE progress_at END,
        operation_deadline=CASE WHEN (completed_items,failed_items,skipped_items) IS DISTINCT FROM
        (CAST(:done AS bigint),CAST(:failed AS bigint),CAST(:skipped AS bigint))
        THEN NOW()+INTERVAL '5 minutes' ELSE operation_deadline END,
        total_items=:total,completed_items=:done,
        failed_items=:failed,skipped_items=:skipped,heartbeat_at=NOW(),updated_at=NOW()
        WHERE job_id=:jid AND stage=:stage AND status='running'""",
        {
            "jid": job_id,
            "stage": stage,
            "total": total,
            "done": completed,
            "failed": failed,
            "skipped": skipped,
        },
    )
    patch = {
        "phase": stage,
        "completed": completed,
        "total": total,
        "label": label or stage,
    }
    execute(
        db,
        """UPDATE jobs SET pipeline_progress=COALESCE(pipeline_progress,'{}'::jsonb) || CAST(:pp AS jsonb),
        updated_at=NOW() WHERE id=:jid""",
        {"jid": job_id, "pp": json.dumps(patch)},
    )
    db.commit()


def _index_map(db, job_id):
    from app.services.disk_manifest import build_index_map

    row = fetchone(db, "SELECT disk_source FROM jobs WHERE id=:id", {"id": job_id})
    ds = row.get("disk_source") or {}
    if isinstance(ds, str):
        ds = json.loads(ds)
    return {path.replace("\\", "/"): uri for path, uri in build_index_map(ds).items()}


def _materialize_full(db, job_id):
    from psycopg2.extras import execute_values

    from app.services.artifact_materialize import materialize_index_entries
    from app.services.disk_manifest import load_index_entries, resolve_part_uri

    row = fetchone(
        db, "SELECT disk_source,files_extracted FROM jobs WHERE id=:id", {"id": job_id}
    )
    manifest = (
        json.loads(row["disk_source"])
        if isinstance(row["disk_source"], str)
        else row["disk_source"] or {}
    )
    by_path = {}
    for entry in load_index_entries(manifest):
        path = (entry.get("path") or "").replace("\\", "/")
        if not path:
            raise RuntimeError("Extracted manifest contains an entry without a path")
        part = resolve_part_uri(manifest, int(entry.get("part_id") or 0))
        if not part:
            raise RuntimeError(f"Extracted part is missing for {path}")
        previous = by_path.get(path)
        if previous and previous.get("sha256") and not entry.get("sha256"):
            continue
        by_path[path] = {**entry, "path": path, "part_uri": part}
    expected = len(by_path)
    if expected < int(row.get("files_extracted") or 0):
        raise RuntimeError(
            f"Extracted manifest accounts for {expected:,} / {int(row['files_extracted']):,} extracted files"
        )
    entries = list(by_path.values())
    # Every extracted file enters inventory. Unsupported/no-text files are
    # explicit stage exceptions, never discarded by hash or path filters.
    result = materialize_index_entries(
        db, job_id, entries, update_status=True, phase1_filter=False
    )
    for start in range(0, len(entries), 1000):
        values = [
            (
                job_id,
                entry["path"],
                json.dumps(
                    {
                        "serial_materialized": True,
                        "extracted_part_uri": entry["part_uri"],
                        "extracted_part_id": entry.get("part_id"),
                        "extracted_part_offset": entry.get("offset"),
                        "source_sha256": entry.get("sha256"),
                    }
                ),
            )
            for entry in entries[start : start + 1000]
        ]
        with db.connection().connection.cursor() as cur:
            execute_values(
                cur,
                """UPDATE job_artifacts AS ja SET metadata=COALESCE(ja.metadata,'{}'::jsonb) || v.meta::jsonb
                FROM (VALUES %s) AS v(job_id,path,meta) WHERE ja.job_id=v.job_id::uuid AND ja.file_path=v.path""",
                values,
                page_size=500,
            )
        db.commit()
    report_progress(
        db,
        job_id,
        "materialize",
        total=expected,
        completed=expected,
        label="Registering all extracted evidence with provenance",
    )
    from app.services.mobile_forensic.key_intake import capture_registered_keys, is_whatsapp_key_path
    if any(is_whatsapp_key_path(entry["path"]) for entry in entries):
        capture_registered_keys(db, job_id)
        db.commit()
    from app.services.mobile_forensic.whatsapp_derivation import materialize_registered_whatsapp_backups
    from app.services.mobile_forensic.whatsapp_crypt import is_whatsapp_crypt_path
    whatsapp = {"encrypted_files": 0, "decrypted_files": 0, "blocked_files": 0,
                "derived_artifacts": 0, "cached_files": 0, "partial_files": 0}
    if any(is_whatsapp_crypt_path(entry["path"]) for entry in entries):
        whatsapp = materialize_registered_whatsapp_backups(
            db, job_id,
            progress=lambda done, total, details: report_progress(
                db, job_id, "materialize", total=expected + total, completed=expected + done,
                label=f"WhatsApp backup decryption — {done} / {total}; {details['blocked_files']} blocked",
            ),
        )
    return {
        **result,
        "total": expected + whatsapp["encrypted_files"],
        "completed": expected + whatsapp["encrypted_files"],
        "expected_files": expected,
        "whatsapp_decryption": whatsapp,
    }


def _parse(db, job_id, schema_name):
    from app.config import get_settings
    from app.services.artifact_parse import parse_job_artifacts_for_paths

    # The execution lock proves no other serial parse runner is alive. Claims
    # left by a killed worker may be reset immediately rather than wait 30 min.
    execute(
        db,
        "UPDATE job_artifacts SET parse_status='pending' WHERE job_id=:jid AND parse_status='parsing'",
        {"jid": job_id},
    )
    db.commit()
    index_map = _index_map(db, job_id)
    total = int(
        fetchone(
            db,
            "SELECT count(*) AS c FROM job_artifacts WHERE job_id=:jid",
            {"jid": job_id},
        )["c"]
    )
    while True:
        row = fetchone(
            db,
            """SELECT count(*) FILTER (WHERE parse_status IN ('pending','parsing')) AS pending,
            count(*) FILTER (WHERE parse_status='parsed') AS done,
            count(*) FILTER (WHERE parse_status IN ('skipped','no_parser')) AS skipped,
        count(*) FILTER (WHERE parse_status IN ('failed','error')) AS failed,count(*) AS total
            FROM job_artifacts WHERE job_id=:jid""",
            {"jid": job_id},
        )
        total = int(row["total"])
        report_progress(
            db,
            job_id,
            "parse",
            total=total,
            completed=int(row["done"]),
            failed=int(row["failed"]),
            skipped=int(row["skipped"]),
            label="Native forensic parsing",
        )
        if int(row["pending"]) <= 0:
            return {
                "status": "ok",
                "total": total,
                "completed": int(row["done"]),
                "failed": int(row["failed"]),
                "skipped": int(row["skipped"]),
            }
        from app.services.job_control import pipeline_should_stop

        if pipeline_should_stop(db, job_id):
            raise StageWaiting("Parsing paused by user")
        parse_job_artifacts_for_paths(
            db,
            job_id,
            paths=None,
            index_map=index_map,
            batch_limit=max(100, int(get_settings().parse_drain_batch_limit or 500)),
            update_status=False,
        )
        db.commit()
        after = int(
            fetchone(
                db,
                """SELECT count(*) AS c FROM job_artifacts
            WHERE job_id=:jid AND parse_status IN ('pending','parsing')""",
                {"jid": job_id},
            )["c"]
        )
        if after >= int(row["pending"]) and after:
            raise StageWaiting(
                "Parsing made no progress; remaining evidence claims must finish"
            )


def _recovery(db, job_id):
    # Disk filesystem-level recovery remains in the one-time image acquisition.
    # This stage analyzes derived deleted files and preserves those source flags.
    from app.services.deleted_evidence import detect_deleted_path_hint

    last = NIL_ID
    tagged = total = 0
    while True:
        rows = fetchall(
            db,
            """SELECT id,file_path,metadata FROM job_artifacts
            WHERE job_id=:jid AND id>:last ORDER BY id LIMIT 1000""",
            {"jid": job_id, "last": last},
        )
        if not rows:
            break
        for row in rows:
            hint = detect_deleted_path_hint(row["file_path"])
            if hint:
                execute(
                    db,
                    """UPDATE job_artifacts SET metadata=CAST(:hint AS jsonb) || COALESCE(metadata,'{}'::jsonb),
                    updated_at=NOW() WHERE id=:id""",
                    {"id": row["id"], "hint": json.dumps(hint)},
                )
                tagged += 1
        total += len(rows)
        last = str(rows[-1]["id"])
        report_progress(
            db,
            job_id,
            "recovery",
            total=total,
            completed=total,
            label="Analyzing extracted deleted/recovered evidence",
        )
    return {
        "status": "ok",
        "total": total,
        "completed": total,
        "deleted_sources_tagged": tagged,
        "scope": "derived_evidence; filesystem recovery is performed during extraction",
    }


def _ocr(db, job_id, schema_name):
    from app.config import get_settings
    from app.services.ocr_gpu import (
        count_pending_ocr,
        enqueue_eligible_ocr,
        run_ocr_for_job,
        unload_glm_ocr,
    )
    from app.services.tar_cache import read_file_from_part

    if not get_settings().ocr_enabled:
        return {"status": "skipped", "reason": "ocr_disabled"}
    index_map = _index_map(db, job_id)
    enqueue_eligible_ocr(db, job_id)
    db.commit()
    before = count_pending_ocr(db, job_id)
    if before <= 0:
        return {"status": "ok", "total": 0, "completed": 0}

    def read(path):
        uri = index_map.get(path)
        if uri:
            return read_file_from_part(uri, path)
        if path.startswith("derived/whatsapp_decrypted/"):
            from app.services.mobile_forensic.sqlite_counts import _read_artifact_bytes
            return _read_artifact_bytes(db, job_id, path, max_bytes=768_000_000)
        return None

    from app.services.embedding_gpu import resolve_device
    from app.services.job_control import pipeline_should_stop
    from app.services.job_locks import gpu_heavy_slot

    _device, gpu = resolve_device("cuda")
    with ExitStack() as stack:
        if gpu:
            stack.enter_context(gpu_heavy_slot("serial_ocr", fail_closed=True))
            # Keep one GLM resident across all batches and unload BEFORE returning
            # the GPU permit. Vision review starts after OCR releases its model.
            stack.callback(unload_glm_ocr)
        previous = before
        result = {}
        while previous > 0:
            if pipeline_should_stop(db, job_id):
                raise StageWaiting("OCR paused by user")
            db.commit()
            result = run_ocr_for_job(
                db,
                job_id,
                schema_name=schema_name,
                read_file_fn=read,
                gpu_permit_owned=gpu,
            )
            after = count_pending_ocr(db, job_id)
            report_progress(
                db,
                job_id,
                "ocr",
                total=before,
                completed=max(before - after, 0),
                label="OCR on CUDA; native text on CPU",
            )
            if after > 0 and (after >= previous or result.get("gpu_deferred")):
                raise StageWaiting(
                    f"OCR barrier: {after:,} documents remaining"
                    + ("; CUDA worker required" if result.get("gpu_deferred") else "")
                )
            previous = after
    counts = fetchone(
        db,
        """SELECT count(*) FILTER (WHERE ocr_status='done') AS done,
        count(*) FILTER (WHERE ocr_status='failed') AS failed,count(*) FILTER (WHERE ocr_status='skipped') AS skipped
        FROM job_artifacts WHERE job_id=:jid""",
        {"jid": job_id},
    )
    return {
        **result,
        "total": sum(int(v) for v in counts.values()),
        "completed": int(counts["done"]),
        "failed": int(counts["failed"]),
        "skipped": int(counts["skipped"]),
    }


def _full_text_chunks(rows):
    """Chunk full parsed/OCR text, keeping every parser output and source link."""
    from app.services.dual_rag_index import _chunk_text
    from app.services.forensic_serial_policy import CHUNK_OVERLAP, CHUNK_SIZE

    output = []
    for row in rows:
        norm = row.get("normalized")
        body = json.dumps(norm, ensure_ascii=False, default=str) if norm else ""
        description = json.dumps(row.get("media_review") or {}, ensure_ascii=False) if row.get("media_review") else ""
        review_description = str(row.get('suspicious_activity_description') or '')
        text = (body + "\n" + (row.get("ocr_text") or "") + "\n" + description+'\n'+review_description).replace("\x00", "").strip()
        if text:
            text = f"Evidence file {row['file_path']}\n{text}"
        for idx, chunk in enumerate(
            _chunk_text(text, CHUNK_SIZE, CHUNK_OVERLAP)
        ):
            output.append(
                (
                    str(row["id"]),
                    row["file_path"],
                    idx,
                    chunk,
                    row.get("encyclopedia_artifact_id"),
                )
            )
    return output


def _chunk(db, job_id, *, mobile=False):
    from psycopg2.extras import execute_values

    last = NIL_ID
    total = int(
        fetchone(
            db,
            "SELECT count(*) AS c FROM job_artifacts WHERE job_id=:jid",
            {"jid": job_id},
        )["c"]
    )
    done = int(
        fetchone(
            db,
            """SELECT count(*) AS c FROM job_artifacts WHERE job_id=:jid
        AND metadata->>'serial_chunked'='true' AND metadata->>'serial_chunk_policy'=:policy""",
            {"jid": job_id, "policy": CHUNK_POLICY},
        )["c"]
    )
    from app.services.job_control import pipeline_should_stop

    while True:
        if pipeline_should_stop(db, job_id):
            raise StageWaiting("RAG chunking paused by user")
        rows = fetchall(
            db,
            """SELECT ja.id,ja.file_path,ja.encyclopedia_artifact_id,
            apr.normalized,ocr.ocr_text,ja.metadata->'media_review' AS media_review,
            ja.metadata->>'suspicious_activity_description' AS suspicious_activity_description FROM job_artifacts ja
            LEFT JOIN LATERAL (SELECT jsonb_agg(normalized ORDER BY created_at) AS normalized
                FROM artifact_parse_results WHERE job_artifact_id=ja.id) apr ON true
            LEFT JOIN LATERAL (SELECT string_agg(ocr_text, E'\n' ORDER BY page_index,created_at) AS ocr_text
                FROM ocr_results WHERE job_artifact_id=ja.id) ocr ON true
            WHERE ja.job_id=:jid AND ja.id>:last AND (COALESCE(ja.metadata->>'serial_chunked','false')<>'true' OR COALESCE(ja.metadata->>'serial_chunk_policy','')<>:policy)
            ORDER BY ja.id LIMIT 128""",
            {"jid": job_id, "last": last,"policy":CHUNK_POLICY},
        )
        if not rows:
            break
        rows = [dict(row) for row in rows]
        paths = [r["file_path"] for r in rows]
        execute(
            db,
            """DELETE FROM rag_chunks WHERE job_id=:jid AND file_path=ANY(:paths)
            AND chunk_type IN ('evidence','evidence_skip')""",
            {"jid": job_id, "paths": paths},
        )
        # Four CPU partitions, joined before persistence. This stage never loads a model.
        chunks = []
        for out in bounded_map(_full_text_chunks, (rows[i::4] for i in range(4))):
            chunks.extend(out)
        if chunks:
            values = [
                (
                    job_id,
                    path,
                    idx,
                    content,
                    aid,
                    json.dumps(
                        {"job_artifact_id": artifact_id, "serial_pipeline": True, "chunk_policy":CHUNK_POLICY}
                    ),
                )
                for artifact_id, path, idx, content, aid in chunks
            ]
            with db.connection().connection.cursor() as cur:
                execute_values(
                    cur,
                    """INSERT INTO rag_chunks(job_id,file_path,chunk_index,content,artifact_id,chunk_type,metadata)
                    VALUES %s""",
                    values,
                    template="(%s,%s,%s,%s,%s,'evidence',%s::jsonb)",
                    page_size=500,
                )
        ids = [str(row["id"]) for row in rows]
        with_text = {chunk[0] for chunk in chunks}
        no_text = [artifact_id for artifact_id in ids if artifact_id not in with_text]
        execute(
            db,
            """UPDATE job_artifacts SET metadata=COALESCE(metadata,'{}'::jsonb) ||
            jsonb_build_object('serial_chunked',true,'serial_chunk_policy',CAST(:policy AS text),'serial_chunk_status',
                CASE WHEN id=ANY(CAST(:no_text AS uuid[])) THEN 'no_text' ELSE 'text' END)
            WHERE id=ANY(CAST(:ids AS uuid[]))""",
            {"ids": ids, "no_text": no_text,"policy":CHUNK_POLICY},
        )
        done += len(rows)
        last = str(rows[-1]["id"])
        report_progress(
            db,
            job_id,
            "chunk",
            total=total,
            completed=done,
            label="RAG chunking of complete parsed and OCR evidence",
        )
    if mobile:
        from app.services.mobile_forensic.mobile_rag import (
            index_mobile_artifacts_for_rag,
        )

        mobile_chunks = index_mobile_artifacts_for_rag(
            db, job_id, embed=False, strict=True
        )
        db.commit()
    else:
        mobile_chunks = {}
        from app.services.forensic_profile_index import (
            ensure_os_fact_chunks,
            ensure_profile_fact_chunks,
        )

        # Synthetic facts consume parsed results only, never reopen the source image.
        ensure_profile_fact_chunks(db, job_id, refresh_critical=False)
        ensure_os_fact_chunks(db, job_id, refresh_hives=False)
        db.commit()
    skipped = int(
        fetchone(
            db,
            """SELECT count(*) AS c FROM job_artifacts WHERE job_id=:jid
        AND metadata->>'serial_chunk_status'='no_text'""",
            {"jid": job_id},
        )["c"]
    )
    from app.services.forensic_priority_evidence import chunk_disk_priority_records
    priority_chunks = chunk_disk_priority_records(db, job_id) if not mobile else 0
    return {
        "status": "ok",
        "priority_chunks": priority_chunks,
        "chunk_size": 2500,
        "chunk_overlap": 800,
        "embedding_enabled": False,
        "total": total,
        "completed": max(done - skipped, 0),
        "skipped": skipped,
        "skip_reason": "No parsed or OCR text" if skipped else None,
        "mobile": mobile_chunks,
    }


def execute_stage(db, job_id, stage, *, schema_name, stage_run_id):
    from app.forensic_common.job_types import is_mobile_job

    mobile = is_mobile_job(db, job_id)
    if stage == "materialize":
        return _materialize_full(db, job_id)
    if stage == "parse":
        result = _parse(db, job_id, schema_name)
        if not mobile:
            from app.services.forensic_priority_evidence import (
                run_disk_priority_evidence,
            )
            result["priority"] = run_disk_priority_evidence(db, job_id)
        if mobile:
            from app.services.forensic_serial_mobile import run_mobile_stage

            execute(
                db,
                "UPDATE pipeline_stage_runs SET details=CAST(:details AS jsonb) WHERE id=:sid",
                {
                    "sid": stage_run_id,
                    "details": json.dumps(
                        {
                            "mobile_work_active": True,
                            "native_total": result["total"],
                            "native_completed": result["completed"]
                            + result["skipped"]
                            + result["failed"],
                        }
                    ),
                },
            )
            db.commit()
            result["mobile"] = run_mobile_stage(
                db, job_id, "parse", schema_name=schema_name, stage_run_id=stage_run_id
            )
            result["total"] += int(result["mobile"]["total"])
            result["completed"] += int(result["mobile"]["completed"])
            result["failed"] += int(result["mobile"]["failed"])
        return result
    if stage == "recovery":
        if mobile:
            from app.services.forensic_serial_mobile import run_mobile_stage

            return run_mobile_stage(
                db,
                job_id,
                "recovery",
                schema_name=schema_name,
                stage_run_id=stage_run_id,
            )
        return _recovery(db, job_id)
    if stage == "ocr":
        return _ocr(db, job_id, schema_name)
    if stage == "inventory":
        if mobile:
            from app.services.forensic_serial_mobile import run_mobile_stage

            run_mobile_stage(
                db,
                job_id,
                "normalize",
                schema_name=schema_name,
                stage_run_id=stage_run_id,
            )
        from app.services.catalog_artifact_runner import run_axiom_artifact_inventory

        result = run_axiom_artifact_inventory(db, job_id, schema_name=schema_name)
        from app.services.suspicious_activity import collect_suspicious_activity
        result['suspicious_activity'] = collect_suspicious_activity(db, job_id)
        return result
    if stage == "chunk":
        return _chunk(db, job_id, mobile=mobile)
    if stage == "media_review":
        from app.services.forensic_media_review import run_media_review

        return run_media_review(db, job_id, schema_name=schema_name)
    if stage == "enrichment":
        from app.services.rag_enrich import run_rag_enrichment_until_complete

        def on_batch(stats):
            from app.services.job_control import pipeline_should_stop

            report_progress(
                db,
                job_id,
                "enrichment",
                total=int(stats.get("parse_total") or 0),
                completed=int(stats.get("scanned") or 0),
                label="Full evidence entity / ontology enrichment",
            )
            if pipeline_should_stop(db, job_id):
                raise StageWaiting("Enrichment paused by user")

        result = run_rag_enrichment_until_complete(db, job_id, on_batch=on_batch)
        if not result.get("complete"):
            raise StageWaiting("Enrichment has more evidence batches to process")
        if mobile:
            result = _enrich_mobile(db, job_id, result)
        else:
            result = _enrich_mobile(db, job_id, result, table="forensic_priority_records", prefix="priority")
        return {
            "status": "ok",
            **result,
            "total": result.get("parse_total", 0),
            "completed": result.get("scanned", 0),
        }
    if stage == "graph":
        from app.services.neo4j_sync import sync_job_graph_serial

        result = sync_job_graph_serial(
            db, job_id, schema_name=schema_name, mobile=mobile
        )
        if result.get("status") != "ok":
            raise StageWaiting(
                "Graph synchronization unavailable; graph barrier remains pending"
            )
        return result
    if stage == "validation":
        result = _validate_complete(db, job_id, mobile=mobile)
        if mobile:
            from app.services.forensic_serial_mobile import complete_mobile_analysis

            complete_mobile_analysis(db, job_id, result)
        return result
    raise ValueError(f"Unknown forensic stage: {stage}")


def _enrich_mobile(db, job_id, stats, *, table="mobile_normalized_artifacts", prefix="mobile"):
    """Scan all normalized mobile records with a resumable keyset cursor."""
    from app.services.job_control import pipeline_should_stop
    from app.services.rag_enrich import _SQL_COUNT_RES, persist_enrichment_stats

    total = int(
        fetchone(
            db,
            f"SELECT count(*) AS c FROM {table} WHERE job_id=:jid",
            {"jid": job_id},
        )["c"]
    )
    stats = dict(stats)
    last = stats.get(prefix+"_last_artifact_id") or ""
    scanned = int(stats.get(prefix+"_scanned") or 0)
    by_type = dict(stats.get(prefix+"_entity_by_type") or {})
    columns = ",".join(
        f"COALESCE(SUM(regexp_count(sample, :{kind}_re, 1, 'i')),0) AS {kind}_n"
        for kind in _SQL_COUNT_RES
    )
    while True:
        if pipeline_should_stop(db, job_id):
            raise StageWaiting("Mobile enrichment paused by user")
        params = {
            "jid": job_id,
            "last": last,
            **{f"{kind}_re": pattern for kind, pattern in _SQL_COUNT_RES.items()},
        }
        row = fetchone(
            db,
            f"""WITH batch AS (SELECT artifact_id,data::text AS sample
            FROM {table} WHERE job_id=:jid AND artifact_id>:last ORDER BY artifact_id LIMIT 500)
            SELECT (SELECT artifact_id FROM batch ORDER BY artifact_id DESC LIMIT 1) AS last_id,
                count(*) AS scanned,{columns} FROM batch""",
            params,
        )
        count = int(row["scanned"])
        if count:
            last = row["last_id"]
            scanned += count
            for kind in _SQL_COUNT_RES:
                by_type[kind] = int(by_type.get(kind) or 0) + int(row[f"{kind}_n"])
        stats.update(
            {
                prefix+"_scanned": scanned,
                prefix+"_total": total,
                prefix+"_last_artifact_id": last,
                prefix+"_entity_by_type": by_type,
                prefix+"_complete": not count or scanned >= total,
            }
        )
        persist_enrichment_stats(db, job_id, stats)
        report_progress(
            db,
            job_id,
            "enrichment",
            total=int(stats.get("parse_total") or 0) + total,
            completed=int(stats.get("scanned") or 0) + scanned,
            label=f"Full normalized {prefix} evidence enrichment",
        )
        if stats[prefix+"_complete"]:
            return {
                **stats,
                "parse_total": int(stats.get("parse_total") or 0) + total,
                "scanned": int(stats.get("scanned") or 0) + scanned,
            }


def validate_stage_barrier(db, job_id, stage, result, *, stage_run_id):
    if result.get("status") in {"failed", "error"}:
        raise RuntimeError(
            f"{stage} failed: {result.get('reason') or result.get('error') or result['status']}"
        )
    if result.get("status") in {
        "partial",
        "held",
        "deferred",
        "waiting",
        "retry",
        "paused",
        "stopped",
    }:
        raise StageWaiting(
            f"{stage} barrier: {result.get('reason') or result.get('error') or result['status']}"
        )
    if stage == "media_review" and result.get("status") != "skipped":
        if int(result.get("completed") or 0)+int(result.get("failed") or 0)<int(result.get("total") or 0):
            raise StageWaiting("Media observations have unfinished evidence files")
    if stage == "materialize":
        registered = int(
            fetchone(
                db,
                """SELECT count(*) AS c FROM job_artifacts WHERE job_id=:jid
            AND metadata->>'serial_materialized'='true'""",
                {"jid": job_id},
            )["c"]
        )
        if registered < int(result.get("expected_files") or result.get("total") or 0):
            raise StageWaiting("Materialization has unregistered extracted evidence")
    if stage == "parse":
        pending = fetchone(
            db,
            """SELECT count(*) AS c FROM job_artifacts
            WHERE job_id=:jid AND parse_status IN ('pending','parsing')""",
            {"jid": job_id},
        )["c"]
        if pending:
            raise StageWaiting(f"Parse barrier: {pending:,} evidence files unfinished")
    if stage == "ocr":
        from app.services.ocr_gpu import count_pending_ocr

        if count_pending_ocr(db, job_id) and result.get("status") != "skipped":
            raise StageWaiting("OCR still has pending evidence")
    if stage == "inventory" and not result.get("done"):
        raise StageWaiting("Artifact inventory is unfinished")
    if stage == "chunk":
        pending = fetchone(
            db,
            """SELECT count(*) AS c FROM job_artifacts WHERE job_id=:jid
            AND (COALESCE(metadata->>'serial_chunked','false')<>'true' OR COALESCE(metadata->>'serial_chunk_policy','')<>:policy)""",
            {"jid": job_id,"policy":CHUNK_POLICY},
        )["c"]
        if pending:
            raise StageWaiting(f"Chunk barrier: {pending:,} evidence files unfinished")
        if result.get("mobile"):
            if result["mobile"].get("status") != "ok":
                raise RuntimeError("Normalized mobile chunking did not complete")
            pending_mobile = int(
                fetchone(
                    db,
                    """SELECT count(*) AS c FROM mobile_normalized_artifacts m
                WHERE m.job_id=:jid AND NOT EXISTS (SELECT 1 FROM rag_chunks rc WHERE rc.job_id=:jid
                    AND rc.metadata->>'mobile_artifact_id'=m.artifact_id AND rc.metadata->>'serial_pipeline'='true'
                    AND rc.metadata->>'chunk_policy'=:policy)""",
                    {"jid": job_id,"policy":CHUNK_POLICY},
                )["c"]
            )
            if pending_mobile:
                raise StageWaiting(
                    f"Chunk barrier: {pending_mobile:,} normalized mobile records unfinished"
                )
    pending = fetchone(
        db,
        """SELECT count(*) AS c FROM pipeline_work_items
        WHERE stage_run_id=:sid AND status IN ('pending','running')""",
        {"sid": stage_run_id},
    )["c"]
    if pending:
        raise StageWaiting(f"{stage} barrier: {pending:,} work units unfinished")


def _validate_complete(db, job_id, *, mobile=False):
    from app.services.catalog_artifact_runner import axiom_inventory_progress
    from app.services.forensic_serial_pipeline import (
        TERMINAL,
        extraction_barrier,
        stage_rows,
    )
    from app.services.ocr_gpu import count_pending_ocr

    row = fetchone(db, "SELECT * FROM jobs WHERE id=:id", {"id": job_id})
    ready, reason = extraction_barrier(row)
    if not ready:
        raise StageWaiting(reason)
    registered = int(
        fetchone(
            db,
            """SELECT count(*) AS c FROM job_artifacts WHERE job_id=:jid
        AND metadata->>'serial_materialized'='true'""",
            {"jid": job_id},
        )["c"]
    )
    materialized = next(
        (r for r in stage_rows(db, job_id) if r["stage"] == "materialize"), {}
    )
    details = materialized.get("details") or {}
    expected = int(details.get("expected_files") or row.get("files_extracted") or 0)
    if registered < expected:
        raise StageWaiting(
            f"Completeness check found {expected - registered:,} unregistered extracted files"
        )
    if any(
        r["status"] not in TERMINAL
        for r in stage_rows(db, job_id)
        if r["stage"] != "validation"
    ):
        raise StageWaiting("A prior stage has not passed its barrier")
    pending = fetchone(
        db,
        """SELECT count(*) FILTER (WHERE parse_status IN ('pending','parsing')) AS parse_pending,
        count(*) FILTER (WHERE parse_status IN ('failed','error')) AS parse_failed,
        count(*) FILTER (WHERE parse_status IN ('skipped','no_parser')) AS parse_skipped,
        count(*) FILTER (WHERE ocr_status='failed') AS ocr_failed
        FROM job_artifacts WHERE job_id=:jid""",
        {"jid": job_id},
    )
    ocr_skipped = any(
        r["stage"] == "ocr" and r["status"] == "skipped" for r in stage_rows(db, job_id)
    )
    if (
        pending["parse_pending"]
        or (count_pending_ocr(db, job_id) and not ocr_skipped)
        or not axiom_inventory_progress(db, job_id).get("done")
    ):
        raise StageWaiting(
            "Completeness check found pending parse, OCR or inventory work"
        )
    if mobile:
        missing_mobile = int(
            fetchone(
                db,
                """SELECT count(*) AS c FROM mobile_normalized_artifacts m
            WHERE m.job_id=:jid AND NOT EXISTS (SELECT 1 FROM rag_chunks rc WHERE rc.job_id=:jid
                AND rc.metadata->>'mobile_artifact_id'=m.artifact_id AND rc.metadata->>'serial_pipeline'='true'
                    AND rc.metadata->>'chunk_policy'=:policy)""",
                {"jid": job_id,"policy":CHUNK_POLICY},
            )["c"]
        )
        if missing_mobile:
            raise StageWaiting(
                f"Completeness check found {missing_mobile:,} mobile records without chunks"
            )
    else:
        missing_priority = int(fetchone(db,"""SELECT count(*) AS c FROM forensic_priority_records p
            WHERE p.job_id=:jid AND NOT EXISTS(SELECT 1 FROM rag_chunks rc WHERE rc.job_id=:jid
                AND rc.metadata->>'priority_artifact_id'=p.artifact_id AND rc.metadata->>'chunk_policy'=:policy)""",{"jid":job_id,"policy":CHUNK_POLICY})["c"])
        if missing_priority:
            raise StageWaiting(f"Completeness check found {missing_priority:,} priority records without chunks")
    from app.services.forensic_priority_evidence import priority_record_table
    table = priority_record_table(db, job_id)
    priority_exceptions = 0
    if table:
        priority_exceptions = int(fetchone(db, f"""SELECT count(*) AS c FROM {table} WHERE job_id=:jid
            AND (artifact_type IN ('priority_source_exception','web_storage_source')
                OR data->>'decrypt_failed'='true' OR (artifact_type='app_backup_encrypted' AND data->>'key_available'='false'))""", {"jid":job_id})["c"])
    media_failed = int(fetchone(db,"SELECT count(*) AS c FROM forensic_media_observations WHERE job_id=:jid AND status='failed'",{"jid":job_id})["c"])
    priority_gaps = 0
    coverage_table = fetchone(db,"SELECT to_regclass('mobile_coverage') AS name") if mobile else None
    if coverage_table and coverage_table.get("name"):
        priority_gaps = int(fetchone(db,"""SELECT count(*) AS c FROM mobile_coverage WHERE job_id=:jid
            AND coverage_key LIKE 'priority_%' AND status='acquisition_gap'""",{"jid":job_id})["c"])
    # Failed/skipped evidence is explicitly reported, never silently called complete coverage.
    ds = (
        json.loads(row["disk_source"])
        if isinstance(row.get("disk_source"), str)
        else row.get("disk_source") or {}
    )
    skipped = int(ds.get("files_skipped") or 0)
    work_failed = int(
        fetchone(
            db,
            """SELECT count(*) AS c FROM pipeline_work_items w
        JOIN pipeline_stage_runs s ON s.id=w.stage_run_id WHERE s.job_id=:jid AND w.status='failed'""",
            {"jid": job_id},
        )["c"]
    )
    no_text = int(
        fetchone(
            db,
            """SELECT count(*) AS c FROM job_artifacts WHERE job_id=:jid
        AND metadata->>'serial_chunk_status'='no_text'""",
            {"jid": job_id},
        )["c"]
    )
    return {
        "status": "ok",
        "total": 1,
        "completed": 1,
        "exceptions": {
            **dict(pending),
            "mobile_work_failed": work_failed,
            "files_without_text": no_text,
            "media_review_failed":media_failed,
            "priority_source_exceptions":priority_exceptions,
            "priority_acquisition_gaps":priority_gaps,
        },
        "extraction_skipped": skipped,
        "ocr_disabled": ocr_skipped,
        "coverage_complete": not skipped
        and not work_failed
        and not ocr_skipped
        and not no_text
        and not media_failed
        and not priority_exceptions
        and not priority_gaps
        and not any(int(pending[k] or 0) for k in ("parse_failed", "ocr_failed")),
    }
