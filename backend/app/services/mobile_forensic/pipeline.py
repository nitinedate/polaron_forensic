"""End-to-end, completeness-first mobile forensics analysis pipeline."""

from __future__ import annotations

import logging
import os
from pathlib import PurePosixPath
from typing import Any

from app.services.mobile_forensic.coverage import persist_coverage_snapshot
from app.services.mobile_forensic.discovery import inventory_from_job_artifacts, summarize_inventory
from app.services.mobile_forensic.integrity import load_intake_keys_from_disk_source
from app.services.mobile_forensic.models import InventoryItem, NormalizedArtifact
from app.services.mobile_forensic.plugins import ParseContext, get_plugin_registry
from app.services.mobile_forensic.storage import (
    artifact_counts_by_domain,
    ensure_mobile_case_schema,
    persist_artifacts,
    persist_inventory,
    persist_source_manifest,
    start_analysis_run,
    update_analysis_run,
)

log = logging.getLogger("mobile_forensic.pipeline")


def _read_bytes_factory(db, job_id: str):
    from app.services.mobile_forensic.sqlite_counts import _read_artifact_bytes

    def _read(path: str, max_bytes: int = 120_000_000) -> bytes | None:
        return _read_artifact_bytes(db, job_id, path, max_bytes=max_bytes)

    return _read


def _priority(it: InventoryItem) -> tuple[int, str]:
    p = it.path.lower().replace("\\", "/")
    if p.endswith(("-wal", "-journal", "-shm")):
        return (0, p)
    if p.endswith((".db", ".sqlite", ".sqlite3", ".sqlitedb")):
        if any(x in p for x in ("msgstore", "chatstorage", "whatsapp", "mmssms", "contacts", "calllog")):
            return (1, p)
        return (2, p)
    if it.extension in {".jpg", ".jpeg", ".png", ".heic", ".mp4", ".mov", ".opus", ".pdf", ".docx"}:
        return (3, p)
    return (4, p)


def _capture_recovery_hints(artifact: NormalizedArtifact, context: ParseContext) -> None:
    if artifact.artifact_type not in {"app_message", "sms", "mms"}:
        return
    refs: set[str] = context.extra.setdefault("referenced_media_names", set())
    data = artifact.data or {}
    for key in ("media_name", "media_path", "attachment", "attachment_path"):
        value = data.get(key)
        if not value:
            continue
        name = PurePosixPath(str(value).replace("\\", "/")).name.lower()
        if name:
            refs.add(name)


def _persist_artifact_buffer(db, job_id: str, buffer: list[NormalizedArtifact]) -> int:
    if not buffer:
        return 0
    n = persist_artifacts(db, job_id, buffer)
    buffer.clear()
    try:
        db.flush()
    except Exception:
        pass
    return n


def _checkpoint(db) -> None:
    """Persist long-running progress when the DB/session supports it."""
    if os.environ.get("MOBILE_ANALYSIS_INCREMENTAL_COMMIT", "1").strip().lower() in {"0", "false", "no"}:
        try:
            db.flush()
        except Exception:
            pass
        return
    try:
        db.commit()
    except Exception:
        try:
            db.flush()
        except Exception:
            pass


def run_mobile_analysis_pipeline(
    db,
    job_id: str,
    *,
    platform: str | None = None,
    force: bool = False,
) -> dict[str, Any]:
    """Discover → parse every item → recover → normalize → correlate → RAG.

    There is intentionally no global file-count or row-count cap. Parsers stream
    database rows and artifacts are persisted in bounded buffers so a large phone
    does not need all parsed records resident in Python memory.
    """
    ensure_mobile_case_schema(db)

    from app.db.sql_helpers import fetchone
    from app.services.artifact_selection_catalog import resolve_job_axiom_platform

    row = fetchone(db, "SELECT disk_source FROM jobs WHERE id=:id", {"id": job_id})
    ds = row.get("disk_source") if row else {}
    if isinstance(ds, str):
        import json
        try:
            ds = json.loads(ds)
        except Exception:
            ds = {}
    ds = ds if isinstance(ds, dict) else {}

    plat = platform or resolve_job_axiom_platform(db, job_id) or ds.get("axiom_platform") or "Android"
    run_id = start_analysis_run(db, job_id, platform=str(plat))
    _checkpoint(db)

    try:
        keys = load_intake_keys_from_disk_source(ds)
        from app.services.mobile_forensic.sqlite_counts import discover_whatsapp_keys

        whatsapp_keys = discover_whatsapp_keys(db, job_id)
        from app.services.mobile_forensic.key_intake import persist_captured_keys
        persist_captured_keys(db, job_id, [key for key in whatsapp_keys if key.source != "case_intake"])
        _checkpoint(db)

        manifest = ds.get("evidence_manifest") if isinstance(ds.get("evidence_manifest"), dict) else None
        if manifest:
            persist_source_manifest(db, job_id, manifest)

        from app.services.mobile_forensic.whatsapp_derivation import materialize_registered_whatsapp_backups
        whatsapp_decryption = materialize_registered_whatsapp_backups(db, job_id)
        _checkpoint(db)
        items = inventory_from_job_artifacts(db, job_id)
        if not items:
            from app.services.mobile_forensic.key_intake import persist_decryption_results
            persist_decryption_results(db, job_id, [])
            update_analysis_run(db, run_id, status="completed", phase="complete", inventory_total=0, files_processed=0)
            _checkpoint(db)
            return {"status": "empty", "inventory_total": 0, "artifacts": 0, "summary": {}, "run_id": run_id}

        update_analysis_run(db, run_id, phase="inventory", inventory_total=len(items))

        # Persist the COMPLETE inventory in bounded checkpoints. No 200k truncation.
        inventory_batch = max(250, min(int(os.environ.get("MOBILE_INVENTORY_DB_BATCH", "2500")), 10_000))
        for start in range(0, len(items), inventory_batch):
            persist_inventory(db, job_id, items[start : start + inventory_batch])
            if start and start % (inventory_batch * 4) == 0:
                _checkpoint(db)
        _checkpoint(db)

        context = ParseContext(
            job_id=job_id,
            platform=str(plat),
            source_id=(manifest or {}).get("source_id"),
            whatsapp_key_hex=keys.get("whatsapp_key_hex"),
            whatsapp_legacy_account=keys.get("whatsapp_legacy_account"),
            whatsapp_key_candidates=whatsapp_keys,
            signal_db_key_hex=keys.get("signal_db_key_hex"),
            ios_backup_password=keys.get("ios_backup_password"),
            read_bytes=_read_bytes_factory(db, job_id),
            db=db,
            extra={"referenced_media_names": set(), "evidence_paths": {item.path for item in items},
                   "preserve_whatsapp_plaintext": True, "whatsapp_backup_results": []},
        )
        registry = get_plugin_registry()
        ordered = sorted(items, key=_priority)

        artifact_buffer: list[NormalizedArtifact] = []
        artifact_buffer_size = max(100, min(int(os.environ.get("MOBILE_ARTIFACT_DB_BATCH", "1000")), 5000))
        file_checkpoint = max(50, min(int(os.environ.get("MOBILE_FILE_CHECKPOINT", "500")), 5000))

        parsed_artifacts = 0
        persisted_artifacts = 0
        unsupported = 0
        parse_errors = 0
        files_processed = 0

        update_analysis_run(db, run_id, phase="parsing")
        for idx, item in enumerate(ordered, start=1):
            item.status = "parsing"
            parsers = registry.route(item, context)
            if not parsers:
                item.status = "unsupported"
                unsupported += 1
                files_processed += 1
            else:
                matched = False
                parser_names: list[str] = []
                item_errors: list[str] = []
                for parser in parsers:
                    parser_names.append(parser.name)
                    try:
                        for art in parser.parse(item, context):
                            matched = True
                            parsed_artifacts += 1
                            _capture_recovery_hints(art, context)
                            artifact_buffer.append(art)
                            if len(artifact_buffer) >= artifact_buffer_size:
                                persisted_artifacts += _persist_artifact_buffer(db, job_id, artifact_buffer)
                    except Exception as exc:
                        parse_errors += 1
                        item_errors.append(f"{parser.name}: {str(exc)[:250]}")
                        log.exception("mobile parser %s failed on %s", parser.name, item.path)
                if matched:
                    item.status = "parsed"
                    item.parser = ",".join(parser_names)
                    if item_errors:
                        item.meta["parser_warnings"] = item_errors
                elif item_errors:
                    item.status = "error"
                    item.error = "; ".join(item_errors)[:1000]
                else:
                    item.status = "unsupported"
                    unsupported += 1
                files_processed += 1

            if idx % file_checkpoint == 0 or idx == len(ordered):
                persisted_artifacts += _persist_artifact_buffer(db, job_id, artifact_buffer)
                # Persist exact statuses for this checkpoint window.
                lo = max(0, idx - file_checkpoint)
                persist_inventory(db, job_id, ordered[lo:idx])
                update_analysis_run(
                    db,
                    run_id,
                    phase="parsing",
                    inventory_total=len(items),
                    files_processed=files_processed,
                    artifacts_written=persisted_artifacts,
                    unsupported_files=unsupported,
                    parse_errors=parse_errors,
                    details={"current_file": item.path, "progress_percent": round(idx * 100.0 / len(ordered), 2)},
                )
                _checkpoint(db)

        persisted_artifacts += _persist_artifact_buffer(db, job_id, artifact_buffer)

        from app.services.mobile_forensic.key_intake import persist_decryption_results
        whatsapp_decryption = persist_decryption_results(db, job_id, context.extra["whatsapp_backup_results"])
        _checkpoint(db)

        # Recovery analyzers stream their output too. They use context.extra for
        # message/media references, so all parsed artifacts do not need to stay in RAM.
        update_analysis_run(db, run_id, phase="recovery")
        recovered_count = 0
        recovery_errors = 0
        for analyzer in registry.recovery_analyzers:
            try:
                for art in analyzer.analyze(items, [], context):
                    artifact_buffer.append(art)
                    recovered_count += 1
                    if len(artifact_buffer) >= artifact_buffer_size:
                        persisted_artifacts += _persist_artifact_buffer(db, job_id, artifact_buffer)
            except Exception:
                recovery_errors += 1
                log.exception("recovery analyzer %s failed job=%s", analyzer.name, job_id)
        persisted_artifacts += _persist_artifact_buffer(db, job_id, artifact_buffer)
        _checkpoint(db)

        # Scalable DB-native correlation; no O(messages * media) Python loop.
        rel_n = 0
        try:
            from app.services.mobile_forensic.correlation import correlate_artifacts_db
            rel_n = correlate_artifacts_db(db, job_id)
        except Exception as exc:
            log.warning("mobile correlation skipped job=%s: %s", job_id, exc)

        counts = artifact_counts_by_domain(db, job_id)
        coverage = persist_coverage_snapshot(db, job_id, items, counts)
        _checkpoint(db)

        # Bridge normalized mobile records directly to RAG, including recovered/deleted
        # records. This fixes the old dependency on job_artifacts only.
        update_analysis_run(db, run_id, phase="rag")
        rag_result: dict[str, Any] = {"status": "skipped", "indexed": 0}
        try:
            from app.services.mobile_forensic.mobile_rag import index_mobile_artifacts_for_rag
            rag_result = index_mobile_artifacts_for_rag(db, job_id, force=force)
        except Exception as exc:
            rag_result = {"status": "error", "indexed": 0, "reason": str(exc)[:500]}
            log.warning("mobile RAG indexing skipped job=%s: %s", job_id, exc)
        _checkpoint(db)

        counts = artifact_counts_by_domain(db, job_id)
        summary = summarize_inventory(items)
        summary.update(
            {
                "whatsapp_decryption": whatsapp_decryption,
                "parsed_artifacts": parsed_artifacts,
                "recovered_artifacts": recovered_count,
                "unsupported_files": unsupported,
                "parse_errors": parse_errors,
                "recovery_errors": recovery_errors,
                "persisted": persisted_artifacts,
                "relationships": rel_n,
                "domain_counts": counts,
                "coverage_keys": len(coverage),
                "rag": rag_result,
                "completeness": {
                    "inventory_discovered": len(items),
                    "files_processed": files_processed,
                    "all_files_processed": files_processed == len(items),
                    "global_file_cap": None,
                    "global_row_cap": None,
                },
            }
        )
        update_analysis_run(
            db,
            run_id,
            status="completed",
            phase="complete",
            inventory_total=len(items),
            files_processed=files_processed,
            artifacts_written=persisted_artifacts,
            recovered_written=recovered_count,
            unsupported_files=unsupported,
            parse_errors=parse_errors,
            details={"summary": summary},
        )
        _checkpoint(db)
        return {
            "status": "ok",
            "run_id": run_id,
            "inventory_total": len(items),
            "files_processed": files_processed,
            "artifacts": counts.get("total_artifacts", persisted_artifacts),
            "summary": summary,
            "platform": plat,
            "whatsapp_decryption": whatsapp_decryption,
            "rag": rag_result,
        }
    except Exception as exc:
        try:
            update_analysis_run(db, run_id, status="failed", phase="failed", details={"error": str(exc)[:2000]})
            _checkpoint(db)
        except Exception:
            pass
        raise
