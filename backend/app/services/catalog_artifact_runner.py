"""Post-pipeline artifact inventory — AXIOM-aligned counts persisted to job_axiom_artifact_results."""

from __future__ import annotations

import json
import logging
import re
from typing import Any

from app.db.sql_helpers import execute, fetchall, fetchone
from app.services.artifact_selection_catalog import resolve_job_axiom_platform
from app.services.disk_build_log import write_disk_log

log = logging.getLogger("axiom_artifact_runner")

# Main pipeline completes at this pct; artifact inventory fills remaining progress to 100%.
PIPELINE_PROGRESS_CAP = 85

INVENTORY_STAGE = "artifact_inventory"
INVENTORY_PHASE = "artifact_inventory"


def clear_inventory_runtime_cache(job_id: str) -> None:
    """Drop in-process inventory caches for a job (path token cache, etc.)."""
    try:
        from app.services.inventory_path_cache import clear_path_cache

        clear_path_cache(job_id)
    except Exception:
        pass
    try:
        from app.services.browser_url_inventory import clear_browser_url_cache
        from app.services.encryption_inventory import clear_encryption_count_cache

        clear_browser_url_cache(job_id)
        clear_encryption_count_cache(job_id)
    except Exception:
        pass
    try:
        from app.services.signature_carve_inventory import clear_carve_cache

        clear_carve_cache(job_id)
    except Exception:
        pass


_MIN_ARTIFACTS_FOR_INVENTORY = 500
# Mobile UFED/logical packages are often far smaller than disk images — do not
# block inventory forever waiting for a Windows-scale materialize count.
_MIN_ARTIFACTS_FOR_INVENTORY_MOBILE = 1


def materialized_artifact_count(db, job_id: str) -> int:
    row = fetchone(
        db,
        "SELECT count(*) AS c FROM job_artifacts WHERE job_id=:j",
        {"j": job_id},
    )
    return int(row["c"]) if row else 0


def inventory_results_look_premature(db, job_id: str) -> bool:
    """True when inventory finished with near-all zeros while many files are now registered.

    Happens when inventory raced materialize (path index scanned 0 files) and
    persisted done=0 for USB/Jump Lists/Web Related/etc.
    """
    try:
        from app.forensic_common.job_types import is_mobile_job

        # Mobile/iOS catalogs are sparse by nature — do not wipe and re-loop.
        if is_mobile_job(db, job_id):
            return False
    except Exception:
        pass
    art_n = materialized_artifact_count(db, job_id)
    if art_n < _MIN_ARTIFACTS_FOR_INVENTORY:
        return False
    row = fetchone(
        db,
        """SELECT COUNT(*) AS total,
                  SUM(CASE WHEN COALESCE(artifact_count,0) > 0 THEN 1 ELSE 0 END) AS nonzero
           FROM job_axiom_artifact_results WHERE job_id=:j""",
        {"j": job_id},
    )
    if not row:
        return False
    total = int(row["total"] or 0)
    nonzero = int(row["nonzero"] or 0)
    # Catalog is large but almost nothing counted — classic premature inventory.
    return total >= 100 and nonzero <= max(20, total // 50)


def _min_artifacts_for_inventory(db, job_id: str) -> int:
    try:
        from app.forensic_common.job_types import is_mobile_job

        if is_mobile_job(db, job_id):
            return _MIN_ARTIFACTS_FOR_INVENTORY_MOBILE
    except Exception:
        pass
    return _MIN_ARTIFACTS_FOR_INVENTORY


# Statuses that mean files are still being copied or have not been registered yet.
_PRE_INVENTORY_STATUSES = frozenset({
    "created",
    "registered",
    "awaiting_segments",
    "processing",
    "building_disk",
    "extracting",
    "disk_ready",
    "paused",
    "failed",
})
# Pipeline phases where materialize has already handed off a stable artifact table.
_POST_MATERIALIZE_PHASES = frozenset({
    "parse",
    "ocr",
    "rag",
    "rag_index",
    "artifact_inventory",
    "axiom_artifacts",
    "graph",
    "complete",
    "report",
})


def _job_pipeline_state(db, job_id: str) -> tuple[str, str]:
    try:
        row = fetchone(
            db,
            "SELECT status, pipeline_progress FROM jobs WHERE id=:id",
            {"id": job_id},
        )
    except Exception:
        return "", ""
    if not row:
        return "", ""
    status = str(row.get("status") or "").lower()
    pp = row.get("pipeline_progress") or {}
    if isinstance(pp, str):
        try:
            pp = json.loads(pp)
        except json.JSONDecodeError:
            pp = {}
    phase = str((pp or {}).get("phase") or "") if isinstance(pp, dict) else ""
    return status, phase


def artifacts_ready_for_inventory(db, job_id: str) -> tuple[bool, str]:
    """Gate inventory until job_artifacts are actually materialized.

    A disk extract starts with zero rows. That is expected, not a failure: inventory
    on an empty table persists hollow zeros. The bulk floor (500) only applies while
    materialize is still filling the table. Once that phase has finished, a smaller
    image is inventoried from whatever was registered.
    """
    art_n = materialized_artifact_count(db, job_id)
    min_n = _min_artifacts_for_inventory(db, job_id)
    if art_n >= min_n:
        return True, f"ready ({art_n:,} artifacts)"
    status, phase = _job_pipeline_state(db, job_id)
    materialize_settled = art_n > 0 and (
        status not in _PRE_INVENTORY_STATUSES
        and status not in ("", "indexing", "extracted")
        or phase in _POST_MATERIALIZE_PHASES
    )
    if materialize_settled:
        return True, f"ready ({art_n:,} artifacts)"
    return False, f"waiting_for_artifacts ({art_n:,} < {min_n:,})"


# Per-process cache: never re-run ALTER once a firm schema is known-good.
# Concurrent ADD COLUMN IF NOT EXISTS (even when columns already exist) takes
# AccessExclusiveLock and deadlocks with inventory SELECTs / idle-in-transaction
# workers — freezing /api/jobs and looking like "no jobs" / endless spinners.
_AXIOM_RESULTS_SCHEMA_READY: set[str] = set()
_AXIOM_RESULTS_REQUIRED_COLS: tuple[tuple[str, str], ...] = (
    ("count_domain", "TEXT"),
    ("occurrence_count", "INTEGER"),
    ("unique_count", "INTEGER"),
    ("query_snapshot", "JSONB"),
    ("parser_version", "TEXT"),
    ("confidence", "TEXT"),
)


def _firm_schema_key(db) -> str:
    schema = ""
    try:
        schema = str((getattr(db, "info", None) or {}).get("firm_schema") or "")
    except Exception:
        schema = ""
    if schema:
        return schema
    try:
        row = fetchone(db, "SELECT current_schema() AS s")
        return str((row or {}).get("s") or "") or "_unknown"
    except Exception:
        return "_unknown"


def ensure_job_axiom_results_schema(db) -> None:
    """Ensure count-provenance columns exist (migration 023 / upgraded 010).

    Older firm schemas only had artifact_count/status — SELECT occurrence_count
    then fails hard and blocks Artifacts / Objectives / inventory for every job.

    Hot paths (get_job, inventory load) call this often — never take exclusive
    locks when columns are already present.
    """
    schema_key = _firm_schema_key(db)
    if schema_key in _AXIOM_RESULTS_SCHEMA_READY:
        return

    try:
        present = {
            str(r.get("column_name") or "")
            for r in fetchall(
                db,
                """
                SELECT column_name
                FROM information_schema.columns
                WHERE table_schema = current_schema()
                  AND table_name = 'job_axiom_artifact_results'
                """,
            )
        }
    except Exception as exc:
        log.warning("ensure axiom results schema: column probe failed: %s", exc)
        try:
            db.rollback()
        except Exception:
            pass
        return

    nested = None
    try:
        nested = db.begin_nested()
    except Exception:
        nested = None
    try:
        execute(
            db,
            """
            CREATE TABLE IF NOT EXISTS job_count_reconciliation (
                job_id UUID NOT NULL,
                artifact_id TEXT NOT NULL,
                axiom_export_count BIGINT,
                python_inventory_count BIGINT,
                delta BIGINT,
                delta_reason TEXT,
                query_snapshot JSONB NOT NULL DEFAULT '{}'::jsonb,
                updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
                PRIMARY KEY (job_id, artifact_id)
            )
            """,
        )
        if nested is not None:
            nested.commit()
    except Exception as exc:
        log.warning("ensure job_count_reconciliation failed: %s", exc)
        if nested is not None:
            try:
                nested.rollback()
            except Exception:
                pass

    missing = [col for col, _ddl in _AXIOM_RESULTS_REQUIRED_COLS if col not in present]
    if not missing:
        _AXIOM_RESULTS_SCHEMA_READY.add(schema_key)
        return

    # Only ALTER when something is actually missing. Cap wait so we never join
    # a lock storm if inventory is holding AccessShareLock for a long time.
    try:
        execute(db, "SET LOCAL lock_timeout = '2s'")
    except Exception:
        pass
    for col, ddl in _AXIOM_RESULTS_REQUIRED_COLS:
        if col not in missing:
            continue
        try:
            execute(
                db,
                f"ALTER TABLE job_axiom_artifact_results ADD COLUMN IF NOT EXISTS {col} {ddl}",
            )
        except Exception as exc:
            log.warning("ensure axiom results column %s failed: %s", col, exc)
            try:
                db.rollback()
            except Exception:
                pass
            return
    try:
        db.flush()
    except Exception:
        pass
    _AXIOM_RESULTS_SCHEMA_READY.add(schema_key)


def _inventory_section_snapshot(db, job_id: str, *, schema_name: str | None, platform: str) -> tuple[dict[str, Any], dict[str, int]]:
    """Fresh section inventory + aligned counts (no Redis cache — prevents stale overwrites)."""
    from app.services.artifact_sections import build_job_artifact_sections
    from app.services.catalog_aligned_counts import compute_all_aligned_counts

    section_inventory = build_job_artifact_sections(db, job_id, schema_name=schema_name)
    title_counts = compute_all_aligned_counts(db, job_id, platform)
    return section_inventory, title_counts


def _resolve_axiom_artifact_count(
    db,
    job_id: str,
    *,
    artifact_name: str,
    artifact_id: str,
    collector_counts: dict[str, int],
    section_inventory: dict[str, Any],
) -> tuple[int, str]:
    """AXIOM-only count resolution — collector map is the single source of truth."""
    count = int(collector_counts.get(artifact_id, 0))
    section, item = _find_exact_section_item(section_inventory, artifact_name)
    if item:
        answer = _format_item_answer(section, item)
    else:
        answer = f'Catalog artifact "{artifact_name}" — count {count:,} (AXIOM-aligned).'
    return count, answer


def _persist_single_axiom_row(
    db,
    job_id: str,
    row: dict[str, Any],
    *,
    section_inventory: dict[str, Any],
    count_result: Any | None = None,
    allow_live_count: bool = True,
) -> None:
    """Insert or update one job_axiom_artifact_results row.

    When ``allow_live_count`` is False (gap-close / failed batch), never re-enter
    heavy collectors — persist count 0 so inventory can reach 100%.
    """
    from app.services.catalog_aligned_counts import count_axiom_catalog_artifact_result

    artifact_id = str(row["artifact_id"])
    artifact_name = row.get("artifact_name") or artifact_id
    category = str(row.get("category") or "")
    result = count_result
    if result is None and allow_live_count:
        try:
            result = count_axiom_catalog_artifact_result(
                db,
                job_id,
                artifact_name=artifact_name,
                category=category,
                artifact_id=artifact_id,
            )
        except Exception as exc:
            log.warning("count failed job=%s artifact=%s: %s", job_id, artifact_id, exc)
            # Do NOT rollback here — that would wipe sibling rows in the same batch
            # and leave inventory stuck below 100% (e.g. 690/692).
            result = None
    if result is not None:
        count = result.primary_count
        answer = result.answer_text(artifact_name)
        persist = result.persist_fields()
    else:
        count = 0
        answer = f'Catalog artifact "{artifact_name}" — count 0 (AXIOM-aligned).'
        persist = {
            "artifact_count": 0,
            "occurrence_count": 0,
            "unique_count": None,
            "count_domain": "artifact_record",
            "parser_version": None,
            "confidence": "LOW",
            "query_snapshot": None,
        }
    section, item = _find_exact_section_item(section_inventory, artifact_name)
    if item:
        answer = _format_item_answer(section, item)
        if result is not None and result.primary_count > 0:
            answer = result.answer_text(artifact_name)
    elif result is not None:
        answer = result.answer_text(artifact_name)
    try:
        execute(
            db,
            """INSERT INTO job_axiom_artifact_results
               (job_id, artifact_id, artifact_count, status, answer, error,
                count_domain, occurrence_count, unique_count, query_snapshot, parser_version, confidence,
                updated_at)
               VALUES (:jid, :aid, :cnt, 'done', :ans, NULL,
                       :cd, :oc, :uc, CAST(:qs AS jsonb), :pv, :conf, NOW())
               ON CONFLICT (job_id, artifact_id) DO UPDATE SET
                 artifact_count=EXCLUDED.artifact_count,
                 status='done',
                 answer=EXCLUDED.answer,
                 error=NULL,
                 count_domain=EXCLUDED.count_domain,
                 occurrence_count=EXCLUDED.occurrence_count,
                 unique_count=EXCLUDED.unique_count,
                 query_snapshot=EXCLUDED.query_snapshot,
                 parser_version=EXCLUDED.parser_version,
                 confidence=EXCLUDED.confidence,
                 updated_at=NOW()""",
            {
                "jid": job_id,
                "aid": artifact_id,
                "cnt": count,
                "ans": answer[:8000] if answer else None,
                "cd": persist.get("count_domain"),
                "oc": persist.get("occurrence_count"),
                "uc": persist.get("unique_count"),
                "qs": json.dumps(persist.get("query_snapshot") or {}),
                "pv": persist.get("parser_version"),
                "conf": persist.get("confidence"),
            },
        )
    except Exception as exc:
        log.warning("persist failed job=%s artifact=%s: %s", job_id, artifact_id, exc)
        try:
            db.rollback()
        except Exception:
            pass
        raise


def _persist_axiom_inventory(
    db,
    job_id: str,
    *,
    platform: str,
    schema_name: str | None = None,
    rows: list[dict[str, Any]] | None = None,
    count_results: dict[str, Any] | None = None,
    progress_cb: Any | None = None,
    skip_section_snapshot: bool = False,
) -> int:
    """Write AXIOM-aligned counts incrementally — one batch at a time with live progress."""
    from app.config import get_settings
    from app.services.job_control import pipeline_should_stop

    # Do NOT clear_inventory_runtime_cache here — that wiped the streaming path
    # index after every batch so the next batch rebuilt from ~100 catalog rows
    # and handbook/path fallbacks went wildly wrong.
    settings = get_settings()
    batch_size = max(1, int(settings.axiom_inventory_batch_size or 50))

    target_rows = rows if rows is not None else inventory_scope_rows(db, job_id, platform=platform)
    if not target_rows:
        return 0

    pending_rows = pending_inventory_rows(db, job_id, target_rows)
    if count_results is not None:
        pending_rows = target_rows
    elif not pending_rows:
        return 0

    section_inventory: dict[str, Any] = {}
    if not skip_section_snapshot:
        from app.services.artifact_sections import build_job_artifact_sections

        section_inventory = build_job_artifact_sections(db, job_id, schema_name=schema_name)

    inv_total = len(target_rows)
    inv_before = axiom_inventory_progress(db, job_id)
    completed_before = int(inv_before.get("completed") or 0)
    if completed_before <= 0:
        write_disk_log(
            db,
            job_id,
            f"Artifact inventory batch started — {inv_total:,} {platform} artifacts in scope",
            stage=INVENTORY_STAGE,
            metadata={"platform": platform, "total": inv_total, "batch_size": batch_size},
        )
        db.flush()

    written = 0
    last_heartbeat = 0.0
    import time as _time

    for batch_start in range(0, len(pending_rows), batch_size):
        if pipeline_should_stop(db, job_id):
            break
        batch = pending_rows[batch_start: batch_start + batch_size]
        for row in batch:
            artifact_id = str(row["artifact_id"])
            artifact_name = str(row.get("artifact_name") or artifact_id)
            now = _time.monotonic()
            if now - last_heartbeat >= 30.0:
                last_heartbeat = now
                write_disk_log(
                    db,
                    job_id,
                    f"Counting catalog artifacts… next: {artifact_name} "
                    f"({completed_before + written:,} / {inv_total:,})",
                    stage=INVENTORY_STAGE,
                    metadata={
                        "artifact_id": artifact_id,
                        "completed": completed_before + written,
                        "total": inv_total,
                    },
                )
                _apply_inventory_progress(
                    db,
                    job_id,
                    completed=completed_before + written,
                    total=inv_total,
                    platform=platform,
                    done=False,
                    stage="counting",
                )
                db.commit()
            result = count_results.get(artifact_id) if count_results is not None else None
            # Precomputed batch / gap-close: missing keys → persist 0, never re-hang collectors.
            allow_live = count_results is None
            _persist_single_axiom_row(
                db,
                job_id,
                row,
                section_inventory=section_inventory,
                count_result=result,
                allow_live_count=allow_live,
            )
            written += 1
            if progress_cb and written % 25 == 0:
                progress_cb(
                    f"Persisted {completed_before + written:,} / {inv_total:,} artifact counts",
                    completed_before + written,
                    inv_total,
                )

        db.commit()
        inv = axiom_inventory_progress(db, job_id)
        _apply_inventory_progress(
            db,
            job_id,
            completed=int(inv["completed"]),
            total=int(inv["total"]),
            platform=platform,
            stage="counting" if not inv.get("done") else "done",
            done=bool(inv["done"]),
        )
        write_disk_log(
            db,
            job_id,
            f"Artifact inventory batch — {int(inv['completed']):,} / {int(inv['total']):,} counted",
            stage=INVENTORY_STAGE,
            metadata={
                "platform": platform,
                "completed": int(inv["completed"]),
                "total": int(inv["total"]),
                "batch_written": len(batch),
            },
        )
        db.commit()

    inv_after = axiom_inventory_progress(db, job_id)
    if bool(inv_after.get("done")):
        write_disk_log(
            db,
            job_id,
            f"Artifact inventory batch complete — {int(inv_after['total']):,} {platform} artifacts counted",
            stage=INVENTORY_STAGE,
            metadata={"platform": platform, "total": int(inv_after["total"])},
        )
        db.flush()
    return written


def _artifact_rows_for_platform(db, platform: str) -> list[dict[str, Any]]:
    from app.db.sql_helpers import rollback_aborted_transaction

    rollback_aborted_transaction(db)
    return fetchall(
        db,
        """SELECT artifact_id, artifact_name, category, prompt_question
           FROM public.axiom_artifacts
           WHERE platform=:p
           ORDER BY sort_order, artifact_name""",
        {"p": platform},
    )


def _progress_label(completed: int, total: int, platform: str, *, done: bool = False) -> str:
    if done:
        return f"Artifact inventory complete — {total:,} artifacts ({platform})"
    return f"Artifact inventory — {completed:,} / {total:,} ({platform})"


# Prewarm occupies ~1–18%; catalog counting occupies 18–99%; done = 100.
_INVENTORY_UI_STAGE_PCT: dict[str, int] = {
    "start": 1,
    "census_start": 2,
    "census_documents": 3,
    "census_media": 6,
    "census_lnk": 8,
    "census_done": 9,
    "path_index": 12,
    "carve": 15,
    "warm_url": 16,
    "warm_encryption": 17,
    "skip_warm": 17,
    "prewarm_done": 18,
}


def inventory_ui_pct_for(
    *,
    stage: str,
    count_idx: int = 0,
    count_total: int = 1,
) -> int:
    """Deterministic inventory bar percent. Never returns 0 while a stage is active."""
    stage_key = (stage or "").strip().lower()
    if stage_key in ("done", "complete"):
        return 100
    if stage_key == "counting":
        if count_total <= 0:
            return 18
        frac = min(1.0, max(0, int(count_idx)) / float(count_total))
        return min(99, 18 + int(81 * frac))
    return _INVENTORY_UI_STAGE_PCT.get(stage_key, 2)


def _stored_enabled_keys(db, job_id: str) -> list[str]:
    enabled_row = fetchone(db, "SELECT sections FROM artifact_scope WHERE job_id=:jid", {"jid": job_id})
    enabled: list[str] = []
    if enabled_row and enabled_row.get("sections"):
        stored = enabled_row["sections"]
        if isinstance(stored, str):
            stored = json.loads(stored)
        if isinstance(stored, list) and stored and isinstance(stored[0], str):
            enabled = stored
    return enabled


def inventory_scope_rows(db, job_id: str, platform: str | None = None) -> list[dict[str, Any]]:
    """Artifact rows in scope for inventory — full catalog unless user saved a subset."""
    platform = platform or resolve_job_axiom_platform(db, job_id)
    try:
        from app.services.catalog_ingest import ensure_platform_axiom_catalog

        ensure_platform_axiom_catalog(db, platform)
    except Exception:
        pass
    all_rows = _artifact_rows_for_platform(db, platform)
    enabled = _stored_enabled_keys(db, job_id)
    if enabled:
        # Remap Android template ids onto iOS (and vice versa) before filtering.
        try:
            from app.services.report_template_service import remap_artifact_ids_to_platform

            enabled = remap_artifact_ids_to_platform(
                db, enabled, target_platform=str(platform or "Windows")
            ) or enabled
        except Exception:
            pass
        enabled_set = set(enabled)
        scoped = [row for row in all_rows if row.get("artifact_id") in enabled_set]
        if scoped:
            return scoped
        # Wrong-platform selection (e.g. Android AX-* on an iOS job) — inventory full catalog.
        log.warning(
            "inventory scope ids mismatch platform=%s job=%s enabled=%s — using full catalog",
            platform,
            job_id,
            len(enabled_set),
        )
    return all_rows


def pending_inventory_rows(db, job_id: str, rows: list[dict[str, Any]]) -> list[dict[str, Any]]:
    done_rows = fetchall(
        db,
        """SELECT artifact_id FROM job_axiom_artifact_results
           WHERE job_id=:jid AND status='done'""",
        {"jid": job_id},
    )
    done_ids = {str(r["artifact_id"]) for r in done_rows}
    return [row for row in rows if str(row.get("artifact_id")) not in done_ids]


def _apply_inventory_progress(
    db,
    job_id: str,
    *,
    completed: int,
    total: int,
    platform: str,
    done: bool,
    ui_pct: int | None = None,
    stage: str | None = None,
    label: str | None = None,
) -> None:
    """Persist inventory progress. Never clobber a finalized pipeline when done=True.

    ``inventory_ui_pct`` is the authoritative UI bar (prewarm + counting).
    ``completed``/``total`` remain for catalog labels; do not treat prewarm
    completed values as "counts finished".
    """
    # Keep existing orchestration/label when updating mid-run so GET polls don't
    # briefly wipe agent cards; only replace phase/counts/label fields.
    row = fetchone(db, "SELECT pipeline_progress, status FROM jobs WHERE id=:id", {"id": job_id})
    pp: dict[str, Any] = {}
    if row and row.get("pipeline_progress"):
        existing = row["pipeline_progress"]
        if isinstance(existing, str):
            try:
                existing = json.loads(existing)
            except json.JSONDecodeError:
                existing = {}
        if isinstance(existing, dict):
            pp = dict(existing)
    existing_phase = str(pp.get("phase") or "")
    existing_status = ((row or {}).get("status") or "").lower()
    # Inventory already finalized — do not reopen ONLY when counts are truly done.
    # If catalog grew (e.g. 626→635) or items remain pending, resume counting.
    if done and existing_phase == "complete" and existing_status in (
        "ready",
        "completed",
        "classified",
        "report_ready",
        "report_generating",
    ):
        return
    if done and existing_status in ("ready", "completed", "classified", "report_ready", "report_generating"):
        return
    if done:
        status = "indexed"
        pct = 100
        resolved_stage = stage or "done"
        resolved_ui = 100
    else:
        status = "indexing"
        pct = _progress_pct(completed, total)
        resolved_stage = stage or str(pp.get("inventory_stage") or "") or None
        if ui_pct is not None:
            resolved_ui = max(1, min(99, int(ui_pct)))
        elif resolved_stage:
            resolved_ui = inventory_ui_pct_for(
                stage=resolved_stage,
                count_idx=completed,
                count_total=total,
            )
        elif total > 0:
            resolved_ui = max(1, min(99, int(100 * completed / total)))
        else:
            resolved_ui = 1
    # Preserve orchestration agent cards; only refresh inventory phase/counts/label.
    pp["phase"] = INVENTORY_PHASE
    pp["completed"] = completed
    pp["total"] = total
    pp["inventory_ui_pct"] = resolved_ui
    if resolved_stage:
        pp["inventory_stage"] = resolved_stage
    if label:
        pp["label"] = label
    else:
        pp["label"] = _progress_label(completed, total, platform, done=done)
    from app.services.forensic_serial_policy import current_stage

    if current_stage() == "inventory":
        status = "indexing"
        pct = min(pct, 99)
    execute(
        db,
        """UPDATE jobs SET status=:st, progress_pct=:pct,
           pipeline_progress=CAST(:pp AS jsonb), updated_at=NOW() WHERE id=:id""",
        {
            "id": job_id,
            "st": status,
            "pct": pct,
            "pp": json.dumps(pp),
        },
    )
    if current_stage() == "inventory":
        from app.services.forensic_serial_pipeline import persist_snapshot

        persist_snapshot(db, job_id)


def job_inventory_is_complete(db, job_id: str) -> bool:
    """True when every in-scope artifact has a done row in job_axiom_artifact_results."""
    return bool(axiom_inventory_progress(db, job_id).get("done"))


def should_skip_pipeline_sync_on_read(db, job_id: str, *, row: dict | None = None) -> bool:
    """Skip expensive orchestration DB writes on GET during active processing."""
    if row is None:
        row = fetchone(db, "SELECT status, pipeline_progress FROM jobs WHERE id=:id", {"id": job_id})
    if not row:
        return False
    status = (row.get("status") or "").lower()
    if status == "indexing" and parse_pending_count(db, job_id) > 0:
        return True
    inv = axiom_inventory_progress(db, job_id)
    if status == "indexing" and int(inv.get("total") or 0) > 0 and not inv.get("done"):
        return True
    if not inv.get("done"):
        return False
    status = (row.get("status") or "").lower()
    if status not in (
        "indexed",
        "ready",
        "completed",
        "classified",
        "report_ready",
        "report_generating",
    ):
        return False
    pp = row.get("pipeline_progress") or {}
    if isinstance(pp, str):
        pp = json.loads(pp)
    phase = (pp or {}).get("phase") or ""
    if phase == "complete":
        return True
    orch = (pp or {}).get("orchestration") if isinstance(pp, dict) else None
    if isinstance(orch, dict) and int(orch.get("overall_pct") or 0) >= 100:
        # Orchestration already finalized in the blob — skip expensive GET writes.
        return True
    # Inventory counts finished but phase not finalized yet — allow sync to finalize.
    return False


def refresh_stored_artifact_progress(db, job_id: str) -> dict[str, Any]:
    """Recompute and persist AXIOM-aligned counts for all catalog artifacts."""
    from app.services.pipeline_orchestrator import merge_orchestration_into_progress

    platform = resolve_job_axiom_platform(db, job_id)
    _persist_axiom_inventory(db, job_id, platform=platform)
    inv = axiom_inventory_progress(db, job_id)
    if int(inv.get("total") or 0) <= 0:
        merged = merge_orchestration_into_progress(db, job_id)
        return {"inventory": inv, "pipeline_progress": merged}

    completed = int(inv["completed"])
    total = int(inv["total"])
    platform = inv.get("platform") or "Windows"
    if inv["done"]:
        # Do not reopen artifact_inventory phase — finalize to ready/complete.
        merged = merge_orchestration_into_progress(db, job_id)
        return {"inventory": inv, "pipeline_progress": merged}

    new_pp = {
        "phase": INVENTORY_PHASE,
        "completed": completed,
        "total": total,
        "label": _progress_label(completed, total, platform, done=False),
    }
    row = fetchone(db, "SELECT status, pipeline_progress FROM jobs WHERE id=:id", {"id": job_id})
    status = (row.get("status") or "").lower() if row else "created"
    existing_pp = row.get("pipeline_progress") if row else None
    if isinstance(existing_pp, str):
        try:
            existing_pp = json.loads(existing_pp)
        except json.JSONDecodeError:
            existing_pp = {}
    if isinstance(existing_pp, dict) and existing_pp.get("orchestration"):
        new_pp["orchestration"] = existing_pp["orchestration"]
    post_extract = {
        "artifacts_registered",
        "parsed",
        "extracted",
        "indexing",
        "indexed",
        "ready",
        "report_ready",
        "report_generating",
        "completed",
        "classified",
    }
    if status in post_extract:
        new_status = "indexing"
    else:
        new_status = status
    pct = _progress_pct(completed, total)
    execute(
        db,
        """UPDATE jobs SET status=:st, progress_pct=:pct,
           pipeline_progress=CAST(:pp AS jsonb), updated_at=NOW() WHERE id=:id""",
        {"id": job_id, "st": new_status, "pct": pct, "pp": json.dumps(new_pp)},
    )
    db.flush()
    merged = merge_orchestration_into_progress(db, job_id)
    return {"inventory": inv, "pipeline_progress": merged}


def axiom_inventory_progress(db, job_id: str) -> dict[str, Any]:
    platform = resolve_job_axiom_platform(db, job_id)
    try:
        from app.services.catalog_ingest import ensure_platform_axiom_catalog

        ensure_platform_axiom_catalog(db, platform)
    except Exception:
        pass
    total_row = fetchone(
        db,
        "SELECT count(*) c FROM public.axiom_artifacts WHERE platform=:p",
        {"p": platform},
    )
    catalog_total = int(total_row["c"]) if total_row else 0
    done_row = fetchone(
        db,
        """SELECT count(*) c FROM job_axiom_artifact_results
           WHERE job_id=:jid AND status='done'""",
        {"jid": job_id},
    )
    done = int(done_row["c"]) if done_row else 0

    enabled = _stored_enabled_keys(db, job_id)
    total = len(inventory_scope_rows(db, job_id, platform=platform))
    if total <= 0:
        total = catalog_total

    return {
        "platform": platform,
        "total": total,
        "catalog_total": catalog_total,
        "completed": done,
        "done": total > 0 and done >= total,
    }


def parse_pending_count(db, job_id: str) -> int:
    from app.services.artifact_parse import count_pending_parse

    return count_pending_parse(db, job_id)


def inventory_pipeline_active(
    *,
    parse_pending: int,
    inv_total: int,
    inv_completed: int,
    inv_done: bool,
    phase: str,
    inventory_in_flight: bool,
    inventory_started: bool,
) -> bool:
    """True when artifact inventory should drive pipeline_progress (not merely catalog exists)."""
    if inv_total <= 0:
        return False
    if parse_pending > 0:
        return False
    # Truly finished — stop rewriting inventory progress.
    if inv_done:
        return False
    # Incomplete counts always keep the inventory phase active, even if a prior
    # finalize set phase=complete / status=ready too early (catalog grew later).
    if inv_completed < inv_total:
        return True
    if inv_completed > 0:
        return True
    if inventory_in_flight:
        return True
    if phase in (INVENTORY_PHASE, "axiom_artifacts", "complete") and inventory_started:
        return True
    return False


def artifact_inventory_pipeline_active(db, job_id: str, *, phase: str = "") -> bool:
    inv = axiom_inventory_progress(db, job_id)
    started = bool(
        fetchone(
            db,
            """SELECT 1 FROM disk_build_logs
               WHERE job_id=:jid AND stage=:st LIMIT 1""",
            {"jid": job_id, "st": INVENTORY_STAGE},
        )
    )
    return inventory_pipeline_active(
        parse_pending=parse_pending_count(db, job_id),
        inv_total=int(inv.get("total") or 0),
        inv_completed=int(inv.get("completed") or 0),
        inv_done=bool(inv.get("done")),
        phase=phase,
        inventory_in_flight=inventory_task_in_flight(db, job_id),
        inventory_started=started,
    )


def _progress_pct(completed: int, total: int) -> int:
    if total <= 0:
        return 100
    span = 100 - PIPELINE_PROGRESS_CAP
    return min(100, PIPELINE_PROGRESS_CAP + int(span * completed / total))


def _normalize_title(value: str) -> str:
    text = re.sub(r"\s+", " ", (value or "").strip().lower())
    return text.lstrip("$")


# Catalog artifact names that differ slightly from report collector titles.
_COLLECTOR_TITLE_ALIASES: dict[str, str] = {
    "jump lists": "jump list",
    "pictures": "picture",
    "logfile analysis": "logfile analysis",
    "web chat urls": "web chat urls",
    "social media urls": "social media urls",
    "email and calendar": "email & calendar",
    "encryption and credentials": "encryption & credentials",
    "encryption / anti-forensics tools": "encryption / anti-forensics tools",
    "eml(x) files": "eml(x) files",
    "outlook 11 emails": "outlook emails",
    "outlook web app email inbox": "outlook web app email inbox",
    "outlook webmail inbox": "outlook webmail inbox",
    # Connected Devices — Axiom catalog labels vs section collectors
    "your phone devices": "your phone device",
    "your phone contacts": "your phone device",
    "remote desktop protocol": "remote desktop protocol (rdp)",
    "installed programs": "installed programs (non-microsoft)",
}


def _title_matches_collector(artifact_name: str, collector_title: str) -> bool:
    a = _normalize_title(artifact_name)
    c = _normalize_title(collector_title)
    if a == c:
        return True
    alias = _COLLECTOR_TITLE_ALIASES.get(a)
    return alias is not None and alias == c


def _find_exact_section_item(
    section_inventory: dict[str, Any],
    artifact_name: str,
) -> tuple[dict[str, Any] | None, dict[str, Any] | None]:
    """Return (section, item) when a collector title matches the catalog artifact name."""
    if not _normalize_title(artifact_name):
        return None, None
    for section in section_inventory.get("sections") or []:
        for item in section.get("items") or []:
            if _title_matches_collector(artifact_name, item.get("title") or ""):
                return section, item
    return None, None


def _format_item_answer(section: dict[str, Any], item: dict[str, Any]) -> str:
    from app.services.artifact_sections import format_multi_section_answer

    return format_multi_section_answer(
        [{"level": "item", "section": section, "item": item}],
        report_style=True,
    )


def clear_artifact_inventory_results(db, job_id: str) -> None:
    execute(
        db,
        "DELETE FROM job_axiom_artifact_results WHERE job_id=:jid",
        {"jid": job_id},
    )
    clear_inventory_runtime_cache(job_id)


def rerun_artifact_inventory(db, job_id: str, *, schema_name: str) -> dict[str, Any]:
    """Clear prior results and recompute AXIOM-aligned counts (synchronous, no LLM)."""
    clear_artifact_inventory_results(db, job_id)
    platform = resolve_job_axiom_platform(db, job_id)
    written = _persist_axiom_inventory(db, job_id, platform=platform, schema_name=schema_name)
    inv = axiom_inventory_progress(db, job_id)
    _apply_inventory_progress(
        db,
        job_id,
        completed=int(inv["completed"]),
        total=int(inv["total"]),
        platform=platform,
        done=bool(inv["done"]),
    )
    write_disk_log(
        db,
        job_id,
        f"Artifact inventory rerun complete — {written:,} AXIOM-aligned counts persisted",
        stage=INVENTORY_STAGE,
        metadata={"written": written, "platform": platform},
    )
    db.commit()
    return {"queued": False, "written": written, **inv}


def run_axiom_artifact_inventory(db, job_id: str, *, schema_name: str | None = None) -> dict[str, Any]:
    """Persist AXIOM-aligned counts for all in-scope catalog artifacts (single pass).

    V45.2: the whole run is wrapped in ``InventoryLiveness`` — the Redis job
    lock is refreshed every 45 s and a liveness line naming the current
    sub-step is written every 90 s, so a slow pre-count step can no longer be
    mistaken for a dead worker (double dispatch) and the operator can see which
    step is consuming the time.
    """
    from app.services.inventory_liveness import InventoryLiveness

    with InventoryLiveness(schema_name, job_id) as live:
        try:
            result = _run_axiom_artifact_inventory_impl(db, job_id, schema_name=schema_name, live=live)
        finally:
            try:
                summary = live.summary()
                write_disk_log(
                    db,
                    job_id,
                    "Artifact inventory step timings — "
                    + ", ".join(f"{k} {v:,.0f}s" for k, v in list(summary.items())[:8]),
                    stage=INVENTORY_STAGE,
                    metadata={"step_timings_sec": summary, "total_sec": round(live.elapsed(), 1)},
                )
                db.commit()
            except Exception:
                try:
                    db.rollback()
                except Exception:
                    pass
    return result


def _run_axiom_artifact_inventory_impl(
    db, job_id: str, *, schema_name: str | None = None, live: Any = None
) -> dict[str, Any]:
    from app.services.job_control import pipeline_should_stop
    from app.services.pipeline_orchestrator import log_agent, merge_orchestration_into_progress

    _mark = (live.step if live is not None else (lambda *a, **k: None))
    _mark("results schema ensure")
    ensure_job_axiom_results_schema(db)
    if pipeline_should_stop(db, job_id):
        inv = axiom_inventory_progress(db, job_id)
        return {
            "status": "stopped",
            "reason": "stop_requested",
            "platform": inv.get("platform"),
            "total": int(inv.get("total") or 0),
            "completed": int(inv.get("completed") or 0),
            "done": bool(inv.get("done")),
        }

    ready, ready_reason = artifacts_ready_for_inventory(db, job_id)
    if not ready:
        # Extraction / materialize has not registered files yet. Stay quiet so the
        # disk log is not filled with a warning on every worker retry.
        if not str(ready_reason).startswith("waiting_for_artifacts"):
            write_disk_log(
                db,
                job_id,
                f"Artifact inventory deferred — {ready_reason}",
                stage=INVENTORY_STAGE,
            )
        try:
            db.commit()
        except Exception:
            pass
        return {
            "status": "deferred",
            "reason": ready_reason,
            "platform": resolve_job_axiom_platform(db, job_id),
            "total": 0,
            "completed": 0,
            "done": False,
        }

    # Hollow prior run (path index scanned 0 files) — wipe before recounting.
    if inventory_results_look_premature(db, job_id):
        log.warning("clearing premature inventory results job=%s", job_id)
        clear_artifact_inventory_results(db, job_id)
        clear_inventory_runtime_cache(job_id)
        try:
            db.commit()
        except Exception:
            try:
                db.rollback()
            except Exception:
                pass

    _mark("catalog ensure")
    platform = resolve_job_axiom_platform(db, job_id)
    try:
        from app.services.catalog_ingest import ensure_platform_axiom_catalog

        ensure_platform_axiom_catalog(db, platform)
    except Exception as exc:
        log.warning("catalog ensure before inventory failed job=%s: %s", job_id, exc)
    _mark("scope rows")
    scoped_rows = inventory_scope_rows(db, job_id, platform=platform)
    total = len(scoped_rows)
    if total <= 0:
        # Do NOT mark the job finished — empty catalog is a recoverable gap.
        write_disk_log(
            db,
            job_id,
            f"Artifact inventory waiting — no catalog rows for platform {platform}",
            stage=INVENTORY_STAGE,
            level="warning",
            metadata={"platform": platform},
        )
        try:
            db.commit()
        except Exception:
            pass
        return {"status": "deferred", "reason": "no_artifacts_for_platform", "platform": platform}

    inv_now = axiom_inventory_progress(db, job_id)
    if inv_now.get("done") and int(inv_now.get("completed") or 0) >= total:
        return {
            "status": "ok",
            "reason": "already_done",
            "platform": platform,
            "total": total,
            "completed": int(inv_now.get("completed") or 0),
            "done": True,
        }

    start_completed = int(inv_now.get("completed") or 0)
    _apply_inventory_progress(
        db,
        job_id,
        completed=start_completed,
        total=total,
        platform=platform,
        done=False,
        stage="counting" if start_completed > 0 else "start",
        label=(
            _progress_label(start_completed, total, platform, done=False)
            if start_completed > 0
            else f"Artifact inventory — preparing ({platform})"
        ),
    )
    write_disk_log(
        db,
        job_id,
        f"Artifact inventory — AXIOM-aligned pass ({total:,} in scope)",
        stage=INVENTORY_STAGE,
        metadata={"platform": platform, "total": total},
    )
    log_agent(
        db,
        job_id,
        "artifacts_agent",
        f"Artifact inventory — AXIOM-aligned counts ({total:,} artifacts)",
        stage=INVENTORY_STAGE,
        metadata={"platform": platform, "total": total},
    )
    merge_orchestration_into_progress(db, job_id)
    db.commit()

    _mark("collector cache reset")
    from app.services.mobile_forensic.detection import is_mobile_job

    mobile_job = is_mobile_job(db, job_id)

    # Fresh inventory run — drop stale collector caches from prior passes.
    try:
        from app.services.browser_url_inventory import clear_browser_url_cache
        from app.services.encryption_inventory import clear_encryption_count_cache

        clear_browser_url_cache(job_id)
        clear_encryption_count_cache(job_id)
    except Exception:
        pass

    if mobile_job:
        # Mobile path — never run disk/EWF extension census.
        # Do not force-rebuild deleted carve on every pass (that hung inventory for minutes).
        try:
            from app.services.mobile_forensic.inventory import persist_mobile_inventory_snapshot

            already = int((axiom_inventory_progress(db, job_id) or {}).get("completed") or 0)
            # Resume / gap-close: skip heavy SQLite prewarm; board refresh runs at the end.
            if already <= 0:
                snap = persist_mobile_inventory_snapshot(db, job_id, force=False)
                write_disk_log(
                    db,
                    job_id,
                    f"Mobile forensic inventory — {snap.get('total_files', 0)} files; "
                    f"WhatsApp messages={snap.get('counts', {}).get('whatsapp_messages', 0)}, "
                    f"chats={snap.get('counts', {}).get('whatsapp_chats', 0)}, "
                    f"SMS={snap.get('counts', {}).get('sms', 0)} "
                    f"(AXIOM-style SQLite/path counts; disk census skipped)",
                    stage=INVENTORY_STAGE,
                    metadata={
                        "platform": snap.get("platform"),
                        "counts": snap.get("counts"),
                        "limitations": snap.get("limitations"),
                        "db_paths": snap.get("db_paths"),
                    },
                )
                db.commit()
            else:
                write_disk_log(
                    db,
                    job_id,
                    f"Skipping mobile SQLite prewarm — resuming inventory ({already:,} already counted)",
                    stage=INVENTORY_STAGE,
                    metadata={"completed": already},
                )
                db.commit()
        except Exception as exc:
            log.warning("mobile forensic inventory prewarm failed job=%s: %s", job_id, exc)
            try:
                db.rollback()
            except Exception:
                pass
    else:
        # Disk/image path — one full-disk extension census (documents + media + LNK).
        # Import only via disk_forensic so mobile packages never pull this module.
        try:
            from app.disk_forensic.census import ensure_disk_extension_censuses

            def _census_progress(message: str, meta: dict | None = None) -> None:
                msg_l = (message or "").lower()
                if "document" in msg_l:
                    stage = "census_documents"
                elif "media" in msg_l or "picture" in msg_l:
                    stage = "census_media"
                elif "lnk" in msg_l or "combined" in msg_l or "complete" in msg_l:
                    stage = "census_done" if ("complete" in msg_l or "combined" in msg_l) else "census_lnk"
                else:
                    stage = "census_start"
                ui_pct = inventory_ui_pct_for(stage=stage)
                ui_done = max(1, min(total - 1, int(total * ui_pct / 100))) if total > 1 else 1
                write_disk_log(
                    db,
                    job_id,
                    message,
                    stage=INVENTORY_STAGE,
                    metadata={
                        **(meta or {}),
                        "completed": ui_done,
                        "total": total,
                        "prewarm": True,
                        "inventory_ui_pct": ui_pct,
                        "inventory_stage": stage,
                    },
                )
                try:
                    _apply_inventory_progress(
                        db,
                        job_id,
                        completed=ui_done,
                        total=total,
                        platform=platform,
                        done=False,
                        stage=stage,
                        ui_pct=ui_pct,
                        label=f"Artifact inventory — {message} ({ui_pct}%)",
                    )
                    from app.services.pipeline_orchestrator import merge_orchestration_into_progress

                    merge_orchestration_into_progress(db, job_id)
                except Exception:
                    pass
                try:
                    db.commit()
                except Exception:
                    try:
                        db.rollback()
                    except Exception:
                        pass

            _mark("extension census")
            ensure_disk_extension_censuses(db, job_id, on_progress=_census_progress)
        except Exception as exc:
            log.warning("disk extension census prewarm failed job=%s: %s", job_id, exc)

    # Release any locks before the long parallel count phase so /api/jobs stays responsive.
    try:
        db.commit()
    except Exception:
        try:
            db.rollback()
        except Exception:
            pass

    from app.services.catalog_aligned_counts import compute_all_aligned_count_results

    count_results: dict[str, Any] = {}

    def _count_progress(
        message: str,
        idx: int,
        total: int,
        *,
        stage: str | None = None,
        path_frac: float | None = None,
    ) -> None:
        if idx == 0 or idx == 1 or idx == total or idx % 5 == 0 or path_frac is not None:
            from app.services.job_locks import DEFAULT_INVENTORY_LOCK_TTL_SEC, refresh_job_lock

            refresh_job_lock("inventory", job_id, ttl_sec=DEFAULT_INVENTORY_LOCK_TTL_SEC)
            msg_l = (message or "").lower()
            if idx <= 0:
                if stage:
                    resolved_stage = stage
                elif "path" in msg_l or "index" in msg_l:
                    resolved_stage = "path_index"
                elif "carve" in msg_l or "signature" in msg_l:
                    resolved_stage = "carve"
                elif "url" in msg_l:
                    resolved_stage = "warm_url"
                elif "encrypt" in msg_l:
                    resolved_stage = "warm_encryption"
                elif "skip" in msg_l:
                    resolved_stage = "skip_warm"
                else:
                    resolved_stage = "prewarm_done"
                ui_pct = inventory_ui_pct_for(stage=resolved_stage)
                if resolved_stage == "path_index" and path_frac is not None:
                    ui_pct = min(14, 12 + int(2 * max(0.0, min(1.0, path_frac))))
                ui_done = max(1, min(max(total - 1, 1), int(total * ui_pct / 100))) if total else 1
                label = f"Artifact inventory — {message} ({ui_pct}%)"
            else:
                resolved_stage = "counting"
                _mark("counting catalog", idx=idx, total=total)
                ui_pct = inventory_ui_pct_for(
                    stage="counting",
                    count_idx=idx,
                    count_total=total,
                )
                ui_done = min(idx, max(total - 1, 1))
                label = _progress_label(ui_done, total, platform, done=False)
            write_disk_log(
                db,
                job_id,
                (
                    f"Counting catalog artifacts… {message} ({idx:,} / {total:,})"
                    if idx > 0
                    else f"Artifact inventory — {message}"
                ),
                stage=INVENTORY_STAGE,
                metadata={
                    "completed": ui_done,
                    "total": total,
                    "raw_idx": idx,
                    "inventory_ui_pct": ui_pct,
                    "inventory_stage": resolved_stage,
                },
            )
            _apply_inventory_progress(
                db,
                job_id,
                completed=ui_done,
                total=total,
                platform=platform,
                done=False,
                stage=resolved_stage,
                ui_pct=ui_pct,
                label=label,
            )
            try:
                merge_orchestration_into_progress(db, job_id)
            except Exception:
                pass
            try:
                db.commit()
            except Exception:
                try:
                    db.rollback()
                except Exception:
                    pass

    # Count + persist in streaming batches so a mid-run crash keeps durable progress
    # and concurrent jobs stay on the same paced path.
    from app.config import get_settings as _get_settings

    stream_batch = max(25, int(getattr(_get_settings(), "axiom_inventory_batch_size", 50) or 50))
    written = 0
    count_results: dict[str, Any] = {}

    try:
        from app.services.inventory_path_cache import (
            ensure_fallback_path_counts,
            get_fallback_path_count,
            seed_fallback_path_counts,
        )

        if mobile_job:
            # Mobile uses SQLite/path collectors — Windows path-token index is a long no-op hang.
            _count_progress(
                "Skipping Windows path-token index (mobile job)",
                0,
                total,
                stage="path_index",
            )
            seed_fallback_path_counts(job_id, scoped_rows)
        else:
            _mark("path-token index")
            _count_progress("Building streaming path index", 0, total, stage="path_index")
            ensure_fallback_path_counts(
                db,
                job_id,
                scoped_rows,
                progress_cb=lambda msg, a, b: _count_progress(
                    msg,
                    0,
                    total,
                    stage="path_index",
                    path_frac=(float(a) / float(b)) if b else 0.0,
                ),
            )
        art_n = materialized_artifact_count(db, job_id)
        # Path index empty while files exist → abort; do not persist hollow zeros.
        sample_aid = str((scoped_rows[0] or {}).get("artifact_id") or "") if scoped_rows else ""
        if (
            (not mobile_job)
            and art_n >= _MIN_ARTIFACTS_FOR_INVENTORY
            and sample_aid
            and get_fallback_path_count(job_id, sample_aid) is None
        ):
            raise RuntimeError(
                f"path index not ready with {art_n:,} job_artifacts — refusing hollow inventory"
            )

        # Single-flight carve warm before parallel counts (avoids 4× unalloc scans).
        if not mobile_job:
            try:
                import threading

                from app.services.signature_carve_inventory import ensure_signature_carve_inventory

                _count_progress(
                    "Signature carving (unallocated / containers)",
                    0,
                    total,
                    stage="carve",
                )
                carve_stop = threading.Event()
                schema_name_hb = schema_name
                if not schema_name_hb:
                    try:
                        sch = fetchone(db, "SELECT current_schema() AS s")
                        schema_name_hb = str((sch or {}).get("s") or "") or None
                        if schema_name_hb in (None, "", "public"):
                            schema_name_hb = None
                    except Exception:
                        schema_name_hb = None

                def _carve_heartbeat() -> None:
                    """Keep inventory_ui_pct alive during long carve (separate DB session)."""
                    ticks = 0
                    while not carve_stop.wait(25.0):
                        ticks += 1
                        if not schema_name_hb:
                            continue
                        try:
                            from app.db.session import firm_session
                            from app.services.pipeline_orchestrator import (
                                merge_orchestration_into_progress,
                            )

                            with firm_session(schema_name_hb) as hb_db:
                                elapsed = ticks * 25
                                _apply_inventory_progress(
                                    hb_db,
                                    job_id,
                                    completed=max(1, int(total * 0.15)),
                                    total=total,
                                    platform=platform,
                                    done=False,
                                    stage="carve",
                                    ui_pct=min(17, 15 + (ticks % 3)),
                                    label=(
                                        f"Artifact inventory — signature carving "
                                        f"({elapsed}s elapsed)"
                                    ),
                                )
                                merge_orchestration_into_progress(hb_db, job_id)
                        except Exception:
                            pass

                hb_thread = threading.Thread(
                    target=_carve_heartbeat,
                    name=f"inv-carve-hb-{job_id[:8]}",
                    daemon=True,
                )
                hb_thread.start()
                try:
                    ensure_signature_carve_inventory(db, job_id)
                finally:
                    carve_stop.set()
                    hb_thread.join(timeout=2.0)
                _count_progress(
                    "Signature carving complete",
                    0,
                    total,
                    stage="carve",
                )
            except Exception as carve_exc:
                log.warning("signature carve warm failed job=%s: %s", job_id, carve_exc)

        # Heavy URL/encryption warms previously hung inventory for minutes:
        # - encryption warm did JSON::text ILIKE over all parse rows + ZIP header scans
        # - mobile jobs do not need Windows browser/encryption collectors at all
        # Collectors still resolve lazily for the few catalog rows that need them.
        if mobile_job:
            _count_progress(
                "Skipping Windows URL/encryption warm (mobile job)",
                0,
                total,
                stage="skip_warm",
            )
        elif art_n >= 80_000:
            _count_progress(
                f"Skipping heavy encryption warm ({art_n:,} files) — warming URLs only",
                0,
                total,
                stage="warm_url",
            )
            try:
                from app.services.browser_url_inventory import compute_communication_url_totals

                compute_communication_url_totals(db, job_id)
            except Exception:
                pass
        else:
            try:
                from app.services.browser_url_inventory import compute_communication_url_totals

                _count_progress("Warming URL inventory", 0, total, stage="warm_url")
                compute_communication_url_totals(db, job_id)
            except Exception:
                pass
            try:
                from app.services.encryption_inventory import compute_report_encryption_counts

                _count_progress(
                    "Warming encryption inventory (path heuristics)",
                    0,
                    total,
                    stage="warm_encryption",
                )
                # Fast path only — never deep-scan during warm (hangs disk + mobile).
                compute_report_encryption_counts(db, job_id, scan_encrypted=False)
            except Exception:
                pass
        _count_progress("Prewarm complete — counting catalog", 0, total, stage="prewarm_done")
    except Exception as exc:
        log.warning("inventory warm failed job=%s: %s", job_id, exc)
        # Fail closed — do not count with an empty path index / unready artifacts.
        if "path index not ready" in str(exc) or "job_artifacts empty" in str(exc):
            write_disk_log(
                db,
                job_id,
                f"Artifact inventory aborted — {exc}",
                stage=INVENTORY_STAGE,
            )
            try:
                db.commit()
            except Exception:
                pass
            return {
                "status": "deferred",
                "reason": str(exc),
                "platform": platform,
                "total": total,
                "completed": 0,
                "done": False,
            }

    pending_scope = list(scoped_rows)
    # Skip artifacts already persisted as done so resume is cheap / consistent.
    try:
        done_ids = {
            str(r["artifact_id"])
            for r in fetchall(
                db,
                """SELECT artifact_id FROM job_axiom_artifact_results
                   WHERE job_id=:j AND status='done'""",
                {"j": job_id},
            )
        }
        if done_ids:
            pending_scope = [r for r in pending_scope if str(r.get("artifact_id")) not in done_ids]
    except Exception:
        pass

    offset_done = total - len(pending_scope)
    for batch_start in range(0, len(pending_scope), stream_batch):
        if pipeline_should_stop(db, job_id):
            break
        batch = pending_scope[batch_start: batch_start + stream_batch]

        def _batch_progress(
            message: str,
            idx: int,
            _batch_total: int,
            *,
            _bs: int = batch_start,
        ) -> None:
            global_idx = offset_done + _bs + idx
            _count_progress(message, min(global_idx, total), total)

        try:
            batch_results = compute_all_aligned_count_results(
                db,
                job_id,
                platform,
                progress_cb=_batch_progress,
                schema_name=schema_name,
                rows=batch,
                skip_warm=True,
            )
            count_results.update(batch_results)
        except Exception as exc:
            log.warning("batch axiom count failed job=%s offset=%s: %s", job_id, batch_start, exc)
            batch_results = {}

        # Keep {} (failed batch) — do not coerce to None (that re-enters live counters).
        written += _persist_axiom_inventory(
            db,
            job_id,
            platform=platform,
            schema_name=schema_name,
            rows=batch,
            skip_section_snapshot=True,
            count_results=batch_results if isinstance(batch_results, dict) else {},
        )

    # Any catalog rows that never got a done result (batch errors / mid-run scope drift)
    # must be closed out — otherwise progress sticks at 645/655 forever and finalize never runs.
    try:
        leftovers = pending_inventory_rows(db, job_id, scoped_rows)
        if leftovers:
            write_disk_log(
                db,
                job_id,
                f"Closing {len(leftovers):,} inventory gaps with zero counts",
                stage=INVENTORY_STAGE,
                level="warning",
                metadata={"count": len(leftovers)},
            )
            written += _persist_axiom_inventory(
                db,
                job_id,
                platform=platform,
                schema_name=schema_name,
                rows=leftovers,
                skip_section_snapshot=True,
                count_results={},
            )
    except Exception as exc:
        log.warning("inventory gap close failed job=%s: %s", job_id, exc)

    try:
        if mobile_job:
            from app.services.mobile_forensic.inventory import persist_mobile_inventory_snapshot

            # Reuse deleted-pipeline cache; only force when board never persisted.
            board = persist_mobile_inventory_snapshot(db, job_id, force=False)
            write_disk_log(
                db,
                job_id,
                f"Mobile artifact board — "
                f"{sum(1 for v in (board.get('counts') or {}).values() if int(v or 0) > 0)}/"
                f"{len(board.get('counts') or {})} families with evidence "
                f"({board.get('total_files', 0)} files indexed)",
                stage=INVENTORY_STAGE,
                metadata={
                    "counts": board.get("counts"),
                    "total_files": board.get("total_files"),
                    "limitations": board.get("limitations"),
                },
            )
    except Exception as exc:
        log.warning("mobile artifact board failed job=%s: %s", job_id, exc)

    nested = None
    try:
        from app.services.investigation_header_service import suggest_investigation_scope
        from app.services.catalog_reconciliation_service import refresh_reconciliation_stub

        try:
            nested = db.begin_nested()
        except Exception:
            nested = None
        intake_row = fetchone(db, "SELECT case_type, report_type, incident_summary FROM case_intake WHERE job_id=:jid", {"jid": job_id})
        suggest_investigation_scope(
            db,
            job_id,
            case_type=(intake_row or {}).get("case_type"),
            report_type=(intake_row or {}).get("report_type"),
            intake_allegations=(intake_row or {}).get("incident_summary"),
        )
        refresh_reconciliation_stub(db, job_id)
        if nested is not None:
            nested.commit()
    except Exception as exc:
        log.warning("post-inventory hooks failed job=%s: %s", job_id, exc)
        try:
            if nested is not None:
                nested.rollback()
        except Exception:
            pass

    # Mobile-only: iOS/Android catalog can grow mid-run (RPT-* report template rows).
    # Re-scope and close gaps so progress cannot stick at e.g. 645/666 forever.
    if mobile_job:
        try:
            for _pass in range(2):
                inv_mid = axiom_inventory_progress(db, job_id)
                if inv_mid.get("done"):
                    break
                fresh_scope = inventory_scope_rows(db, job_id, platform=platform)
                drift = pending_inventory_rows(db, job_id, fresh_scope)
                if not drift:
                    break
                write_disk_log(
                    db,
                    job_id,
                    f"Closing {len(drift):,} mobile catalog drift rows (pass {_pass + 1})",
                    stage=INVENTORY_STAGE,
                    level="warning",
                    metadata={"count": len(drift)},
                )
                written += _persist_axiom_inventory(
                    db,
                    job_id,
                    platform=platform,
                    schema_name=schema_name,
                    rows=drift,
                    skip_section_snapshot=True,
                    count_results={},
                )
                db.commit()
        except Exception as exc:
            log.warning("mobile catalog drift close failed job=%s: %s", job_id, exc)

    inv_after = axiom_inventory_progress(db, job_id)
    completed = int(inv_after["completed"])
    inv_total = int(inv_after["total"])
    all_done = bool(inv_after["done"])
    # Mobile safety: if a race still leaves a tiny gap, finalize on completed scope
    # rather than leaving the job indexing forever.
    if mobile_job and not all_done and completed > 0 and inv_total > 0 and completed >= inv_total - 5:
        try:
            fresh_scope = inventory_scope_rows(db, job_id, platform=platform)
            drift = pending_inventory_rows(db, job_id, fresh_scope)
            if drift:
                written += _persist_axiom_inventory(
                    db,
                    job_id,
                    platform=platform,
                    schema_name=schema_name,
                    rows=drift,
                    skip_section_snapshot=True,
                    count_results={},
                )
            inv_after = axiom_inventory_progress(db, job_id)
            completed = int(inv_after["completed"])
            inv_total = int(inv_after["total"])
            all_done = bool(inv_after["done"]) or completed >= inv_total > 0
        except Exception as exc:
            log.warning("mobile inventory finalize safety failed job=%s: %s", job_id, exc)
    _apply_inventory_progress(
        db,
        job_id,
        completed=completed,
        total=inv_total,
        platform=platform,
        done=all_done,
        stage="done" if all_done else "counting",
        ui_pct=100 if all_done else None,
    )
    if all_done:
        write_disk_log(
            db,
            job_id,
            f"Artifact inventory complete — {inv_total:,} {platform} artifacts counted",
            stage=INVENTORY_STAGE,
            metadata={"platform": platform, "total": inv_total},
        )
    merge_orchestration_into_progress(db, job_id)
    db.commit()

    return {
        "status": "ok",
        "platform": platform,
        "total": inv_total,
        "completed": completed,
        "batch": written,
        "done": all_done,
    }


def sync_inventory_pipeline_progress(db, job_id: str) -> dict[str, Any] | None:
    """Refresh job.pipeline_progress from live inventory counts when inventory is already running."""
    inv = axiom_inventory_progress(db, job_id)
    if inv["total"] <= 0:
        return None
    row = fetchone(db, "SELECT status, pipeline_progress FROM jobs WHERE id=:id", {"id": job_id})
    if not row:
        return None
    pp = row.get("pipeline_progress") or {}
    if isinstance(pp, str):
        pp = json.loads(pp)
    phase = (pp or {}).get("phase") or ""
    status = row.get("status") or "created"
    if inv.get("done"):
        # Counts finished; finalize to phase=complete instead of rewriting inventory progress.
        from app.services.pipeline_orchestrator import merge_orchestration_into_progress

        return merge_orchestration_into_progress(db, job_id)
    # Incomplete inventory — reopen even if a prior pass marked complete/ready.
    pre_inventory = status in {
        "created",
        "awaiting_segments",
        "registered",
        "pending",
        "uploaded",
        "processing",
        "building_disk",
        "extracting",
        "paused",
        "failed",
    }
    if pre_inventory and phase in (INVENTORY_PHASE, "axiom_artifacts"):
        execute(db, "UPDATE jobs SET pipeline_progress = NULL, updated_at = NOW() WHERE id=:id", {"id": job_id})
        db.flush()
        return None
    inventory_active = artifact_inventory_pipeline_active(db, job_id, phase=phase)
    if not inventory_active:
        return None
    completed = int(inv["completed"])
    total = int(inv["total"])
    platform = inv.get("platform") or "Windows"
    live_completed = int((pp or {}).get("completed") or 0)
    live_ui = (pp or {}).get("inventory_ui_pct")
    live_stage = str((pp or {}).get("inventory_stage") or "")
    # During prewarm, DB result rows stay at 0 — never regress live UI progress.
    if (
        completed <= 0
        and live_ui is not None
        and live_stage
        and live_stage not in ("counting", "done", "complete")
        and phase == INVENTORY_PHASE
    ):
        return pp
    if (
        (pp or {}).get("completed") == completed
        and (pp or {}).get("total") == total
        and phase == INVENTORY_PHASE
        and (live_ui is None or completed >= live_completed)
    ):
        return pp
    # Preserve orchestration so the UI does not flap while counts update.
    new_pp = dict(pp or {}) if isinstance(pp, dict) else {}
    if completed > 0 or live_stage in ("counting", "done", "complete"):
        new_pp.update(
            {
                "phase": INVENTORY_PHASE,
                "completed": completed,
                "total": total,
                "inventory_stage": "counting",
                "inventory_ui_pct": inventory_ui_pct_for(
                    stage="counting",
                    count_idx=completed,
                    count_total=total,
                ),
                "label": _progress_label(completed, total, platform, done=False),
            }
        )
    else:
        # Keep prewarm fields; only ensure phase/total are consistent.
        new_pp["phase"] = INVENTORY_PHASE
        new_pp["total"] = total
        return new_pp
    pct = _progress_pct(completed, total)
    post_extract = {
        "artifacts_registered",
        "parsed",
        "extracted",
        "indexing",
        "indexed",
        "ready",
        "report_ready",
        "report_generating",
        "completed",
        "classified",
        # Resume inventory even if status was left on an older extract/build value.
        "building_disk",
        "processing",
        "disk_ready",
        "extracting",
    }
    if status in post_extract or completed > 0:
        new_status = "indexing"
    else:
        new_status = status
        pct = row.get("progress_pct") if isinstance(row.get("progress_pct"), int) else None
        if pct is None:
            cur = fetchone(db, "SELECT progress_pct FROM jobs WHERE id=:id", {"id": job_id})
            pct = int(cur["progress_pct"]) if cur and cur.get("progress_pct") is not None else 0
    execute(
        db,
        """UPDATE jobs SET status=:st, progress_pct=:pct,
           pipeline_progress=CAST(:pp AS jsonb), updated_at=NOW() WHERE id=:id""",
        {"id": job_id, "st": new_status, "pct": pct, "pp": json.dumps(new_pp)},
    )
    db.flush()
    return new_pp


def inventory_task_in_flight(db, job_id: str, *, within_sec: float = 1800.0) -> bool:
    """True when artifact inventory Celery work is actively running.

    A held Redis lock is only trusted when the job row was updated recently —
    otherwise a crashed worker would block re-queue for the entire lock TTL.
    """
    from datetime import datetime, timezone

    from app.services.job_locks import force_release_job_lock, job_lock_held

    def _age_sec(ts) -> float:
        if ts is None:
            return 999999.0
        if getattr(ts, "tzinfo", None) is None:
            ts = ts.replace(tzinfo=timezone.utc)
        return max(0.0, (datetime.now(timezone.utc) - ts).total_seconds())

    job_row = fetchone(db, "SELECT updated_at FROM jobs WHERE id=:id", {"id": job_id})
    job_age = _age_sec((job_row or {}).get("updated_at"))

    # Hard stop for duplicate dispatch — but only while the worker is heartbeating.
    if job_lock_held("inventory", job_id):
        if job_age <= 180.0:
            return True
        # Stale lock: worker died mid-count without releasing Redis.
        force_release_job_lock("inventory", job_id)
        log.warning(
            "Released stale inventory lock job=%s (job idle %.0fs)",
            job_id,
            job_age,
        )

    inv = axiom_inventory_progress(db, job_id)
    if inv["done"] or inv["total"] <= 0:
        return False

    activity_row = fetchone(
        db,
        """SELECT timestamp FROM disk_build_logs
           WHERE job_id=:jid AND stage=:st
             AND (
               message ILIKE '%inventory batch%'
               OR message ILIKE '%Counting catalog artifacts%'
               OR message ILIKE '%Artifact inventory liveness%'
               OR message ILIKE '%extension census%'
               OR message ILIKE '%Document disk census%'
               OR message ILIKE '%Media inventory%'
               OR message ILIKE '%AXIOM-aligned pass%'
             )
           ORDER BY timestamp DESC LIMIT 1""",
        {"jid": job_id, "st": INVENTORY_STAGE},
    )
    if activity_row and activity_row.get("timestamp"):
        activity_age = _age_sec(activity_row["timestamp"])
        # Parallel counting logs every few artifacts — 3 minutes without a log = stalled.
        if activity_age < 180.0 and job_age < 180.0:
            return True
        if activity_age > 240.0:
            return False

    fail_row = fetchone(
        db,
        """SELECT timestamp FROM disk_build_logs
           WHERE job_id=:jid AND stage=:st AND level='error'
             AND message ILIKE '%inventory failed%'
           ORDER BY timestamp DESC LIMIT 1""",
        {"jid": job_id, "st": INVENTORY_STAGE},
    )
    if fail_row and fail_row.get("timestamp"):
        start_row = fetchone(
            db,
            """SELECT timestamp FROM disk_build_logs
               WHERE job_id=:jid AND stage=:st
                 AND (
                   message ILIKE '%inventory batch started%'
                   OR message ILIKE '%AXIOM-aligned pass%'
                   OR message ILIKE '%Artifact inventory queued%'
                 )
               ORDER BY timestamp DESC LIMIT 1""",
            {"jid": job_id, "st": INVENTORY_STAGE},
        )
        if start_row and fail_row["timestamp"] >= start_row.get("timestamp"):
            return False

    start_row = fetchone(
        db,
        """SELECT timestamp FROM disk_build_logs
           WHERE job_id=:jid AND stage=:st
             AND (
               message ILIKE '%inventory batch started%'
               OR message ILIKE '%AXIOM-aligned pass%'
               OR message ILIKE '%Artifact inventory queued%'
             )
           ORDER BY timestamp DESC LIMIT 1""",
        {"jid": job_id, "st": INVENTORY_STAGE},
    )
    if not start_row or not start_row.get("timestamp"):
        return False

    finish_row = fetchone(
        db,
        """SELECT timestamp FROM disk_build_logs
           WHERE job_id=:jid AND stage=:st
             AND (
               message ILIKE '%inventory batch complete%'
               OR message ILIKE '%inventory complete —%'
               OR message ILIKE '%Artifact inventory complete —%'
             )
             AND timestamp >= :start_ts
           ORDER BY timestamp DESC LIMIT 1""",
        {"jid": job_id, "st": INVENTORY_STAGE, "start_ts": start_row["timestamp"]},
    )
    if finish_row and finish_row.get("timestamp"):
        return False

    start_age = _age_sec(start_row["timestamp"])
    completed = int(inv.get("completed") or 0)

    # Mobile SQLite prewarm can sit at 0/N for several minutes before first catalog
    # row is written — do not treat that as a dead worker (causes heal spam).
    prewarm_row = fetchone(
        db,
        """SELECT timestamp FROM disk_build_logs
           WHERE job_id=:jid
             AND (
               message ILIKE '%mobile inventory%'
               OR message ILIKE '%SQLite inventory%'
               OR message ILIKE '%persist_mobile_inventory%'
               OR message ILIKE '%prewarm%'
             )
             AND timestamp >= :start_ts
           ORDER BY timestamp DESC LIMIT 1""",
        {"jid": job_id, "start_ts": start_row["timestamp"]},
    )
    if prewarm_row and _age_sec(prewarm_row.get("timestamp")) < 600.0:
        return True

    if completed <= 0 and start_age > 600.0:
        return False

    if start_age < 300.0:
        return True

    if completed > 0 and job_age < 180.0 and start_age < within_sec:
        return True

    return False


def queue_axiom_artifact_inventory(db, job_id: str, *, schema_name: str) -> dict[str, Any]:
    """Queue background artifact inventory — never block the caller on full-disk counting."""
    from app.services.forensic_serial_policy import serial_enabled, current_stage

    if serial_enabled() and current_stage() is None:
        from app.services.forensic_serial_pipeline import start_serial_pipeline
        from app.services.rag_image_evidence import is_image_evidence_job

        if not is_image_evidence_job(db, job_id):
            result = start_serial_pipeline(db, job_id, schema_name=schema_name)
            return {"queued_axiom_inventory": False, "reason": "serial_controller", **result}
    from app.services.artifact_selection_catalog import persist_job_axiom_platform
    from app.services.job_locks import job_lock_held

    ensure_job_axiom_results_schema(db)
    persist_job_axiom_platform(db, job_id)
    ready, ready_reason = artifacts_ready_for_inventory(db, job_id)
    if not ready:
        inv = axiom_inventory_progress(db, job_id)
        # Zero (or still-growing) job_artifacts during disk extract is normal.
        # Do not write a warning the UI treats as a job failure.
        if not str(ready_reason).startswith("waiting_for_artifacts"):
            write_disk_log(
                db,
                job_id,
                f"Artifact inventory not queued — {ready_reason}",
                stage=INVENTORY_STAGE,
                level="warning",
            )
        return {"queued_axiom_inventory": False, "reason": ready_reason, **inv}
    if parse_pending_count(db, job_id) > 0:
        inv = axiom_inventory_progress(db, job_id)
        return {"queued_axiom_inventory": False, "reason": "parse_pending", **inv}
    inv = axiom_inventory_progress(db, job_id)
    if int(inv.get("total") or 0) <= 0:
        return {"queued_axiom_inventory": False, "reason": "no_artifacts", **inv}
    # Invalidate hollow "done" inventories that raced an empty job_artifacts table.
    if inv.get("done") and inventory_results_look_premature(db, job_id):
        log.warning(
            "premature inventory detected job=%s — clearing hollow results for recompute",
            job_id,
        )
        clear_artifact_inventory_results(db, job_id)
        clear_inventory_runtime_cache(job_id)
        inv = axiom_inventory_progress(db, job_id)
        write_disk_log(
            db,
            job_id,
            "Cleared premature artifact inventory (near-all zeros while files are registered) — re-queueing",
            stage=INVENTORY_STAGE,
        )
        db.commit()
    if inv.get("done"):
        return {"queued_axiom_inventory": False, "reason": "already_done", **inv}
    if job_lock_held("inventory", job_id) or inventory_task_in_flight(db, job_id):
        return {"queued_axiom_inventory": True, "reason": "already_running", **inv}

    platform = inv.get("platform") or resolve_job_axiom_platform(db, job_id)
    completed = int(inv.get("completed") or 0)
    total = int(inv.get("total") or 0)
    _apply_inventory_progress(
        db,
        job_id,
        completed=completed,
        total=total,
        platform=platform,
        done=False,
    )
    write_disk_log(
        db,
        job_id,
        f"Artifact inventory queued — {total:,} {platform} artifacts",
        stage=INVENTORY_STAGE,
        metadata={"platform": platform, "total": total, "completed": completed},
    )
    db.commit()

    from app.forensic_common.job_types import is_mobile_job
    from app.tasks import axiom_artifact_inventory_mobile_task, axiom_artifact_inventory_task

    if is_mobile_job(db, job_id):
        axiom_artifact_inventory_mobile_task.delay(schema_name, job_id)
    else:
        axiom_artifact_inventory_task.delay(schema_name, job_id)
    return {"queued_axiom_inventory": True, "reason": "queued", **inv}


def finalize_job_after_pipeline(db, job_id: str, *, schema_name: str) -> dict[str, Any]:
    """Hand off artifact inventory to the disk worker — parse drain must return quickly."""
    return queue_axiom_artifact_inventory(db, job_id, schema_name=schema_name)


def ensure_artifact_inventory(db, job_id: str, *, schema_name: str) -> dict[str, Any]:
    """Queue AXIOM-aligned inventory when counts are missing (async, non-blocking)."""
    inv = axiom_inventory_progress(db, job_id)
    stored = load_stored_axiom_counts(db, job_id)
    if stored and inv.get("done") and not inventory_results_look_premature(db, job_id):
        return {"queued": False, "reason": "stored_counts", **inv}
    if stored and inv.get("done") and inventory_results_look_premature(db, job_id):
        log.warning("ensure_artifact_inventory: premature results job=%s — requeue", job_id)
    job = fetchone(db, "SELECT status FROM jobs WHERE id=:id", {"id": job_id})
    status = (job.get("status") or "").lower() if job else ""
    ready = {
        "artifacts_registered",
        "parsed",
        "extracted",
        "indexing",
        "indexed",
        "ready",
        "completed",
        "classified",
    }
    if status not in ready:
        return {"queued": False, "reason": "pipeline_not_ready", **inv}
    if int(inv.get("total") or 0) <= 0:
        return {"queued": False, "reason": "no_catalog_artifacts", **inv}
    result = queue_axiom_artifact_inventory(db, job_id, schema_name=schema_name)
    queued = bool(result.get("queued_axiom_inventory"))
    reason = str(result.get("reason") or ("queued" if queued else "skipped"))
    return {"queued": queued, "reason": reason, **{k: v for k, v in result.items() if k != "queued_axiom_inventory"}}


def load_stored_axiom_inventory(db, job_id: str) -> dict[str, dict[str, Any]]:
    """Read persisted artifact inventory with count provenance."""
    ensure_job_axiom_results_schema(db)
    rows = fetchall(
        db,
        """SELECT artifact_id, artifact_count, occurrence_count, unique_count,
                  count_domain, query_snapshot, parser_version, confidence, answer, status, updated_at
           FROM job_axiom_artifact_results
           WHERE job_id=:jid""",
        {"jid": job_id},
    )
    out: dict[str, dict[str, Any]] = {}
    for row in rows:
        aid = str(row.get("artifact_id") or "")
        if not aid:
            continue
        qs = row.get("query_snapshot")
        if isinstance(qs, str):
            try:
                qs = json.loads(qs)
            except json.JSONDecodeError:
                qs = {}
        out[aid] = {
            "count": int(row.get("occurrence_count") or row.get("artifact_count") or 0),
            "artifact_count": int(row.get("artifact_count") or 0),
            "occurrence_count": int(row.get("occurrence_count") or row.get("artifact_count") or 0),
            "unique_count": row.get("unique_count"),
            "count_domain": row.get("count_domain"),
            "query_snapshot": qs if isinstance(qs, dict) else {},
            "parser_version": row.get("parser_version"),
            "confidence": row.get("confidence"),
            "answer": (row.get("answer") or "").strip(),
            "status": row.get("status"),
            "query_status": (
                "done"
                if str(row.get("status") or "").lower() not in {"failed", "error"}
                else "failed"
            ),
        }
    return out


def load_stored_axiom_counts(db, job_id: str) -> dict[str, int]:
    """Read persisted artifact counts from job_axiom_artifact_results only."""
    inv = load_stored_axiom_inventory(db, job_id)
    if inv:
        return {aid: int(meta.get("count") or 0) for aid, meta in inv.items()}
    rows = fetchall(
        db,
        """SELECT artifact_id, artifact_count FROM job_axiom_artifact_results
           WHERE job_id=:jid AND status='done'""",
        {"jid": job_id},
    )
    if rows:
        return {str(r["artifact_id"]): int(r["artifact_count"] or 0) for r in rows}
    partial = fetchall(
        db,
        """SELECT artifact_id, artifact_count FROM job_axiom_artifact_results
           WHERE job_id=:jid""",
        {"jid": job_id},
    )
    if partial:
        return {str(r["artifact_id"]): int(r["artifact_count"] or 0) for r in partial}
    return {}


def load_job_axiom_counts(db, job_id: str, platform: str) -> dict[str, int]:
    """Counts for inventory runner — prefers DB; never runs live collectors on read."""
    stored = load_stored_axiom_counts(db, job_id)
    if stored:
        return stored
    return {}


def persist_collector_counts(
    db,
    job_id: str,
    *,
    platform: str | None = None,
    report_only: bool = False,
    progress_cb: Any | None = None,
) -> dict[str, int]:
    """Write AXIOM-aligned collector counts for every in-scope catalog artifact."""
    platform = platform or resolve_job_axiom_platform(db, job_id)
    if report_only:
        _persist_report_template_inventory(db, job_id, platform=platform, progress_cb=progress_cb)
    else:
        _persist_axiom_inventory(db, job_id, platform=platform, progress_cb=progress_cb)
    return load_stored_axiom_counts(db, job_id)


def _report_template_rows(db, platform: str) -> list[dict[str, Any]]:
    from app.services.report_catalog_sync import REPORT_ARTIFACTS

    rows: list[dict[str, Any]] = []
    for art in REPORT_ARTIFACTS:
        row = fetchone(
            db,
            """SELECT artifact_id, artifact_name, category, prompt_question
               FROM public.axiom_artifacts
               WHERE platform=:p AND artifact_name=:n AND category=:c
               LIMIT 1""",
            {"p": platform, "n": art["name"], "c": art["category"]},
        )
        if row:
            rows.append(dict(row))
    return rows


def _persist_report_template_inventory(
    db,
    job_id: str,
    *,
    platform: str,
    progress_cb: Any | None = None,
) -> int:
    """Persist counts for PDF section B report-template artifacts only (fast path)."""
    from app.services.catalog_aligned_counts import count_axiom_catalog_artifact_result

    rows = _report_template_rows(db, platform)
    if not rows:
        return 0

    # Authoritative report/export refresh: discard process-local stale caches and
    # rebuild the shared full-disk inventories once before individual collectors.
    try:
        from app.services.browser_url_inventory import clear_browser_url_cache
        clear_browser_url_cache(job_id)
    except Exception:
        pass
    try:
        from app.services.encryption_inventory import clear_encryption_count_cache
        clear_encryption_count_cache(job_id)
    except Exception:
        pass
    try:
        from app.services.email_mime_inventory import clear_email_mime_scan_cache
        clear_email_mime_scan_cache(job_id)
    except Exception:
        pass
    try:
        from app.services.disk_ext_census import ensure_disk_extension_censuses
        ensure_disk_extension_censuses(db, job_id, force=True)
    except Exception as exc:
        log.warning("authoritative disk census refresh failed job=%s: %s", job_id, exc)
    try:
        from app.services.media_inventory import build_media_disk_inventory
        build_media_disk_inventory(db, job_id, force=True)
    except Exception as exc:
        log.warning("authoritative media refresh failed job=%s: %s", job_id, exc)
    try:
        from app.services.encryption_inventory import compute_report_encryption_counts
        # Deep content/header scan is required for the report's Encrypted Files value.
        compute_report_encryption_counts(db, job_id, scan_encrypted=True)
    except Exception as exc:
        log.warning("authoritative encryption scan failed job=%s: %s", job_id, exc)
    try:
        from app.services.signature_carve_inventory import ensure_signature_carve_inventory
        # Recovered records remain a separate domain, but some mail/document collectors
        # need the persisted carve inventory to report their recovered component.
        ensure_signature_carve_inventory(db, job_id, force=False)
    except Exception as exc:
        log.warning("authoritative signature inventory warm failed job=%s: %s", job_id, exc)
    count_results: dict[str, Any] = {}
    total = len(rows)
    for idx, row in enumerate(rows, start=1):
        aid = str(row["artifact_id"])
        name = str(row.get("artifact_name") or aid)
        if progress_cb:
            progress_cb(f"Counting {name}", idx, total)
        count_results[aid] = count_axiom_catalog_artifact_result(
            db,
            job_id,
            artifact_name=name,
            category=str(row.get("category") or ""),
            artifact_id=aid,
        )
    return _persist_axiom_inventory(
        db,
        job_id,
        platform=platform,
        rows=rows,
        count_results=count_results,
        skip_section_snapshot=True,
    )
