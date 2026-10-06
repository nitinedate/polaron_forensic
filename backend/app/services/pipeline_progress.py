"""Safe merges for jobs.pipeline_progress when RAG and inventory run concurrently."""

from __future__ import annotations

import json
from typing import Any

from app.db.sql_helpers import execute, fetchone

_INVENTORY_KEYS = (
    "inventory_ui_pct",
    "inventory_stage",
)


def parse_pipeline_progress(raw: Any) -> dict[str, Any]:
    if not raw:
        return {}
    if isinstance(raw, str):
        try:
            raw = json.loads(raw)
        except json.JSONDecodeError:
            return {}
    return dict(raw) if isinstance(raw, dict) else {}


def inventory_progress_active(pp: dict[str, Any] | None) -> bool:
    """True while artifact inventory is mid-prewarm or mid-count."""
    if not pp:
        return False
    stage = str(pp.get("inventory_stage") or "")
    ui = pp.get("inventory_ui_pct")
    if stage and stage not in ("done", "complete") and ui is not None and int(ui) < 100:
        return True
    phase = str(pp.get("phase") or "")
    if phase in ("artifact_inventory", "axiom_artifacts") and ui is not None and int(ui) < 100:
        return True
    return False


def merge_pipeline_progress(
    existing: dict[str, Any] | None,
    update: dict[str, Any],
    *,
    writer: str = "generic",
) -> dict[str, Any]:
    """Merge a progress update without wiping concurrent inventory/RAG/orch state."""
    merged = dict(existing or {})
    update = dict(update or {})
    preserved_orch = merged.get("orchestration") if isinstance(merged.get("orchestration"), dict) else None
    preserved_inv = {k: merged[k] for k in _INVENTORY_KEYS if k in merged}
    preserved_inv_label = merged.get("label") if inventory_progress_active(merged) else None
    preserved_inv_completed = merged.get("completed") if inventory_progress_active(merged) else None
    preserved_inv_total = merged.get("total") if inventory_progress_active(merged) else None
    preserved_inv_phase = merged.get("phase") if inventory_progress_active(merged) else None
    preserved_rag = merged.get("rag_progress") if isinstance(merged.get("rag_progress"), dict) else None

    inv_active = inventory_progress_active(merged) or inventory_progress_active({**merged, **update})

    if writer in ("rag", "parse", "ocr") and inv_active and "inventory_stage" not in update:
        # Keep inventory as the top-level phase while it runs; nest RAG counters.
        rag_blob = {
            "phase": update.get("phase") or "rag",
            "completed": update.get("completed"),
            "total": update.get("total"),
            "label": update.get("label"),
        }
        merged["rag_progress"] = {**(preserved_rag or {}), **{k: v for k, v in rag_blob.items() if v is not None}}
        # Do not let RAG overwrite inventory top-level fields.
        if preserved_inv_phase:
            merged["phase"] = preserved_inv_phase
        if preserved_inv_completed is not None:
            merged["completed"] = preserved_inv_completed
        if preserved_inv_total is not None:
            merged["total"] = preserved_inv_total
        if preserved_inv_label:
            merged["label"] = preserved_inv_label
        for k, v in preserved_inv.items():
            merged[k] = v
    else:
        merged.update(update)
        # Restore inventory fields when a non-inventory writer omitted them.
        if writer != "inventory":
            for k, v in preserved_inv.items():
                if k not in update:
                    merged[k] = v
            if preserved_rag and "rag_progress" not in update:
                merged["rag_progress"] = preserved_rag

    if preserved_orch and "orchestration" not in update:
        merged["orchestration"] = preserved_orch
    return merged


def write_merged_pipeline_progress(
    db,
    job_id: str,
    update: dict[str, Any],
    *,
    writer: str = "generic",
    status_sql: str | None = None,
    progress_pct: int | None = None,
    extra_sets: str = "",
    extra_params: dict[str, Any] | None = None,
) -> dict[str, Any]:
    """Read-merge-write jobs.pipeline_progress atomically enough for UI honesty."""
    row = fetchone(db, "SELECT pipeline_progress FROM jobs WHERE id=:id", {"id": job_id})
    existing = parse_pipeline_progress((row or {}).get("pipeline_progress"))
    merged = merge_pipeline_progress(existing, update, writer=writer)
    from app.services.forensic_serial_policy import current_stage

    if current_stage() is not None:
        from app.services.forensic_serial_pipeline import serial_progress_snapshot

        serial = serial_progress_snapshot(db, job_id, row={"pipeline_progress": merged})
        if serial:
            merged = serial
            progress_pct = int(serial["progress_pct"])
            status_sql = "status=CASE WHEN stop_requested OR status='paused' THEN 'paused' ELSE 'indexing' END"
    params: dict[str, Any] = {"id": job_id, "pp": json.dumps(merged)}
    sets = ["pipeline_progress=CAST(:pp AS jsonb)", "updated_at=NOW()"]
    if progress_pct is not None:
        sets.append("progress_pct=:prog")
        params["prog"] = int(progress_pct)
    if status_sql:
        sets.append(status_sql)
    if extra_sets:
        sets.append(extra_sets.strip().rstrip(","))
    if extra_params:
        params.update(extra_params)
    execute(
        db,
        f"UPDATE jobs SET {', '.join(sets)} WHERE id=:id",
        params,
    )
    return merged
