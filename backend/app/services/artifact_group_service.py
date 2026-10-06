"""Persist and resolve per-job artifact group selection for the Artifacts page and report."""

from __future__ import annotations

import json
import logging
from typing import Any

from sqlalchemy.orm import Session

from app.db.sql_helpers import execute, fetchall, fetchone
from app.services.catalog_categories import canonical_category

log = logging.getLogger("artifact_group_service")


def _ensure_table(db: Session) -> None:
    try:
        execute(
            db,
            """CREATE TABLE IF NOT EXISTS job_artifact_groups (
                 job_id UUID NOT NULL REFERENCES jobs(id) ON DELETE CASCADE,
                 group_name TEXT NOT NULL,
                 group_count INTEGER NOT NULL DEFAULT 0,
                 group_description TEXT,
                 enabled BOOLEAN NOT NULL DEFAULT TRUE,
                 artifacts JSONB NOT NULL DEFAULT '[]'::jsonb,
                 updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
                 PRIMARY KEY (job_id, group_name)
               )""",
        )
        db.flush()
    except Exception as exc:
        log.debug("job_artifact_groups ensure skipped: %s", exc)
        db.rollback()


def _artifact_row(
    sub: dict[str, Any],
    *,
    enabled_keys: set[str],
    inventory_map: dict[str, dict[str, Any]] | None = None,
) -> dict[str, Any]:
    key = sub.get("key") or ""
    inv = (inventory_map or {}).get(key) or {}
    inv_count = inv.get("count")
    cat_count = int(sub.get("count") or 0)
    # A persisted per-job inventory result is authoritative for that snapshot.
    # Never take max(stored, catalog): doing so can resurrect stale/high counts
    # after a corrected collector has produced a lower result.
    if inv_count is not None:
        count = int(inv_count)
    else:
        count = cat_count
    description = (
        (inv.get("answer") or "").strip()
        or (sub.get("description") or "").strip()
        or (sub.get("observation_focus") or "").strip()
        or (sub.get("prompt_question") or "").strip()
    )
    enabled = key in enabled_keys
    return {
        "key": key,
        "label": sub.get("label") or key,
        "count": count,
        "description": description[:600] if description else "",
        "enabled": enabled,
        "critical": bool(sub.get("critical")),
        "prompt_question": sub.get("prompt_question"),
        "recovery_method": sub.get("recovery_method"),
        "objective_id": sub.get("objective_id"),
        "count_domain": inv.get("count_domain") or sub.get("count_domain"),
        "query_key": inv.get("query_key") or sub.get("query_key"),
        "query_status": inv.get("query_status") or sub.get("query_status"),
        "observation_focus": inv.get("observation_focus") or sub.get("observation_focus"),
        "parser_version": inv.get("parser_version") or sub.get("parser_version"),
        "confidence": inv.get("confidence") or sub.get("confidence"),
    }


def default_enabled_keys(catalog: dict[str, Any]) -> list[str]:
    """Critical artifacts with count > 0 are on by default; zero-count items stay off."""
    keys: list[str] = []
    for section in catalog.get("sections") or []:
        for sub in section.get("subcategories") or []:
            count = int(sub.get("count") or 0)
            if count <= 0:
                continue
            if sub.get("critical"):
                keys.append(sub["key"])
    return keys


def counts_by_key(
    catalog: dict[str, Any],
    inventory_map: dict[str, dict[str, Any]] | None = None,
) -> dict[str, int]:
    """Resolve artifact_id → count from inventory (preferred) or catalog."""
    inv = inventory_map or {}
    out: dict[str, int] = {}
    for section in catalog.get("sections") or []:
        for sub in section.get("subcategories") or []:
            key = sub.get("key") or ""
            if not key:
                continue
            if key in inv and inv[key].get("count") is not None:
                out[key] = int(inv[key]["count"])
            else:
                out[key] = int(sub.get("count") or 0)
    return out


def strip_zero_count_keys(
    catalog: dict[str, Any],
    enabled_keys: list[str],
    *,
    inventory_map: dict[str, dict[str, Any]] | None = None,
) -> list[str]:
    """Remove zero-count artifact keys — critical items with count 0 must stay unchecked."""
    counts = counts_by_key(catalog, inventory_map)
    return [k for k in enabled_keys if counts.get(k, 0) > 0]


def build_groups_from_catalog(
    catalog: dict[str, Any],
    enabled_keys: set[str],
    *,
    inventory_map: dict[str, dict[str, Any]] | None = None,
) -> list[dict[str, Any]]:
    groups: list[dict[str, Any]] = []
    for section in catalog.get("sections") or []:
        title = canonical_category(section.get("title") or "Other")
        artifacts = [
            _artifact_row(sub, enabled_keys=enabled_keys, inventory_map=inventory_map)
            for sub in section.get("subcategories") or []
        ]
        group_count = sum(int(a.get("count") or 0) for a in artifacts)
        enabled_in_group = [a for a in artifacts if a.get("enabled")]
        group_enabled = len(enabled_in_group) > 0
        desc_parts = [a["description"] for a in enabled_in_group if a.get("description")][:2]
        group_description = " ".join(desc_parts)[:800] if desc_parts else None
        groups.append({
            "group_name": title,
            "group_count": group_count,
            "group_description": group_description,
            "enabled": group_enabled,
            "artifacts": artifacts,
        })
    return groups


def sync_job_artifact_groups(
    db: Session,
    job_id: str,
    groups: list[dict[str, Any]],
) -> None:
    _ensure_table(db)
    execute(db, "DELETE FROM job_artifact_groups WHERE job_id=:jid", {"jid": job_id})
    for group in groups:
        execute(
            db,
            """INSERT INTO job_artifact_groups
               (job_id, group_name, group_count, group_description, enabled, artifacts, updated_at)
               VALUES (:jid, :name, :count, :desc, :enabled, CAST(:arts AS jsonb), NOW())""",
            {
                "jid": job_id,
                "name": group.get("group_name") or "Other",
                "count": int(group.get("group_count") or 0),
                "desc": group.get("group_description"),
                "enabled": bool(group.get("enabled")),
                "arts": json.dumps(group.get("artifacts") or []),
            },
        )
    db.flush()


def load_job_artifact_groups(db: Session, job_id: str) -> list[dict[str, Any]]:
    _ensure_table(db)
    rows = fetchall(
        db,
        """SELECT group_name, group_count, group_description, enabled, artifacts
           FROM job_artifact_groups WHERE job_id=:jid ORDER BY group_name""",
        {"jid": job_id},
    )
    out: list[dict[str, Any]] = []
    for row in rows:
        arts = row.get("artifacts") or []
        if isinstance(arts, str):
            arts = json.loads(arts)
        out.append({
            "group_name": row.get("group_name"),
            "group_count": int(row.get("group_count") or 0),
            "group_description": row.get("group_description"),
            "enabled": bool(row.get("enabled")),
            "artifacts": arts if isinstance(arts, list) else [],
        })
    return out


def enabled_keys_from_groups(groups: list[dict[str, Any]]) -> list[str]:
    keys: list[str] = []
    for group in groups:
        if not group.get("enabled"):
            continue
        for art in group.get("artifacts") or []:
            if art.get("enabled") and art.get("key"):
                keys.append(art["key"])
    return keys


def _load_inventory_map(db: Session, job_id: str) -> dict[str, dict[str, Any]]:
    rows = fetchall(
        db,
        """SELECT r.artifact_id, r.artifact_count, r.occurrence_count, r.unique_count,
                  r.count_domain, r.query_snapshot, r.parser_version, r.confidence, r.answer, r.status,
                  aa.observation_focus, aa.prompt_question, aa.metadata
           FROM job_axiom_artifact_results r
           LEFT JOIN public.axiom_artifacts aa ON aa.artifact_id = r.artifact_id
           WHERE r.job_id=:jid""",
        {"jid": job_id},
    )
    out: dict[str, dict[str, Any]] = {}
    for row in rows:
        aid = row.get("artifact_id")
        if not aid:
            continue
        meta = row.get("metadata") or {}
        if isinstance(meta, str):
            try:
                meta = json.loads(meta)
            except json.JSONDecodeError:
                meta = {}
        qs = row.get("query_snapshot")
        if isinstance(qs, str):
            try:
                qs = json.loads(qs)
            except json.JSONDecodeError:
                qs = {}
        out[aid] = {
            "count": int(row.get("occurrence_count") or row.get("artifact_count") or 0),
            "answer": (row.get("answer") or "").strip(),
            "observation_focus": (row.get("observation_focus") or "").strip(),
            "prompt_question": (row.get("prompt_question") or "").strip(),
            "count_domain": row.get("count_domain") or meta.get("count_domain"),
            "query_key": meta.get("query_key") or (qs or {}).get("query_key") if isinstance(qs, dict) else None,
            "query_status": (
                "done"
                if str(row.get("status") or "").lower() not in {"failed", "error"}
                else "failed"
            ),
            "parser_version": row.get("parser_version"),
            "confidence": row.get("confidence"),
        }
    return out


def resolve_artifact_scope(
    db: Session,
    job_id: str,
    catalog: dict[str, Any],
    *,
    stored_enabled: list[str] | None = None,
    persist: bool = True,
    allow_zero_count: bool = False,
) -> dict[str, Any]:
    """Build group rows + enabled_keys; zero-count items are unchecked unless explicitly saved."""
    inventory_map = _load_inventory_map(db, job_id)
    enabled = list(stored_enabled or [])
    if not enabled:
        enabled = default_enabled_keys(catalog)
    if not allow_zero_count:
        enabled = strip_zero_count_keys(catalog, enabled, inventory_map=inventory_map)
    enabled_set = set(enabled)
    groups = build_groups_from_catalog(catalog, enabled_set, inventory_map=inventory_map)
    if persist:
        try:
            sync_job_artifact_groups(db, job_id, groups)
        except Exception as exc:
            log.warning("artifact group sync failed job=%s: %s", job_id, exc)
            db.rollback()
    return {
        "enabled_keys": enabled_keys_from_groups(groups) or enabled,
        "groups": groups,
        "scope_changed": bool(stored_enabled) and set(stored_enabled) != set(enabled),
    }
