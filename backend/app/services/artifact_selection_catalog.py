"""Axiom artifact selection catalog — loaded from public.axiom_artifacts (Magnet AXIOM 10.2.0)."""

from __future__ import annotations

import json
from typing import Any

from sqlalchemy.orm import Session

from app.db.sql_helpers import execute, fetchone
from app.services.axiom_catalog_ingest import get_axiom_catalog_for_platform, resolve_axiom_platform


def resolve_job_axiom_platform(db: Session, job_id: str) -> str:
    from app.services.mobile_os import mobile_os_to_axiom_platform
    from app.services.mobile_segments import infer_mobile_axiom_platform

    row = fetchone(
        db,
        """SELECT j.disk_source,
                  COALESCE(json_agg(e.original_name) FILTER (WHERE e.original_name IS NOT NULL), '[]') AS evidence_names,
                  COALESCE(json_agg(e.host_path) FILTER (WHERE e.host_path IS NOT NULL), '[]') AS host_paths
           FROM jobs j
           LEFT JOIN evidence_files e ON e.job_id = j.id
           WHERE j.id=:jid
           GROUP BY j.id, j.disk_source""",
        {"jid": job_id},
    )
    ds = row.get("disk_source") if row else None
    if isinstance(ds, str):
        try:
            ds = json.loads(ds)
        except json.JSONDecodeError:
            ds = None
    if isinstance(ds, dict):
        # Examiner-selected Mobile OS always wins.
        if (ds.get("os_selection_source") or "") == "examiner":
            examiner_platform = mobile_os_to_axiom_platform(str(ds.get("mobile_os") or ""))
            if examiner_platform:
                return examiner_platform
        stored = (ds.get("axiom_platform") or ds.get("evidence_platform") or "").strip()
        if stored:
            return stored

    detected = (ds or {}).get("detected_os") if isinstance(ds, dict) else None
    family = (detected or {}).get("family") if isinstance(detected, dict) else None
    if family and family.lower() not in ("unknown", ""):
        return resolve_axiom_platform(family)

    evidence_names = row.get("evidence_names") if row else []
    host_paths = row.get("host_paths") if row else []
    if isinstance(evidence_names, str):
        try:
            evidence_names = json.loads(evidence_names)
        except json.JSONDecodeError:
            evidence_names = []
    if isinstance(host_paths, str):
        try:
            host_paths = json.loads(host_paths)
        except json.JSONDecodeError:
            host_paths = []

    examiner_os = (ds or {}).get("mobile_os") if isinstance(ds, dict) else None
    mobile_platform = infer_mobile_axiom_platform(
        evidence_names=list(evidence_names or []),
        host_paths=list(host_paths or []),
        disk_format=(ds or {}).get("format") if isinstance(ds, dict) else None,
        examiner_mobile_os=str(examiner_os) if examiner_os else None,
    )
    if mobile_platform:
        return mobile_platform

    return resolve_axiom_platform(family)


def persist_job_axiom_platform(db: Session, job_id: str) -> str:
    """Detect and store the AXIOM catalog platform (Windows/Android/iOS/…) on the job."""
    platform = resolve_job_axiom_platform(db, job_id)
    row = fetchone(db, "SELECT disk_source FROM jobs WHERE id=:jid", {"jid": job_id})
    ds = row.get("disk_source") if row else None
    if isinstance(ds, str):
        try:
            ds = json.loads(ds)
        except json.JSONDecodeError:
            ds = {}
    if not isinstance(ds, dict):
        ds = {}
    family = platform.lower()
    examiner = (ds.get("os_selection_source") or "") == "examiner"
    if platform in ("Android", "iOS"):
        ds["detected_os"] = {
            "family": family,
            "confidence": "high" if examiner else "medium",
            "method": "examiner_os" if examiner else "evidence_platform",
            "signals": ["examiner_mobile_os"] if examiner else ["mobile_segments"],
        }
    ds["axiom_platform"] = platform
    ds["evidence_platform"] = platform
    execute(
        db,
        "UPDATE jobs SET disk_source=CAST(:ds AS jsonb), updated_at=NOW() WHERE id=:jid",
        {"ds": json.dumps(ds), "jid": job_id},
    )
    db.flush()
    return platform


def get_selection_artifact_catalog(
    db: Session | None = None,
    *,
    platform: str | None = None,
    job_id: str | None = None,
    counts_by_key: dict[str, int] | None = None,
    read_only: bool = False,
    refresh_collectors: bool | None = None,
) -> dict[str, Any]:
    if db is None:
        return {"sections": [], "platform": platform}
    axiom_platform = platform or "Windows"
    if counts_by_key is None and job_id:
        from app.services.axiom_artifact_runner import load_stored_axiom_counts

        # AXIOM-only: artifact counts always come from persisted inventory (never live merge on read).
        counts_by_key = load_stored_axiom_counts(db, job_id)
        _ = refresh_collectors  # callers persist via persist_collector_counts before refresh
    catalog = get_axiom_catalog_for_platform(db, axiom_platform, counts_by_key=counts_by_key or {})
    if job_id:
        from app.services.axiom_artifact_runner import load_stored_axiom_inventory

        inv = load_stored_axiom_inventory(db, job_id)
        from app.services.axiom_catalog_ingest import catalog_display_status

        for section in catalog.get("sections") or []:
            for sub in section.get("subcategories") or []:
                detail = inv.get(sub.get("key") or "")
                if not detail:
                    sub["query_status"] = catalog_display_status()
                    sub["count"] = int(sub.get("count") or 0)
                    continue
                sub["query_status"] = catalog_display_status(
                    stored_status=str(detail.get("status") or detail.get("query_status") or "done")
                )
                sub["count_domain"] = detail.get("count_domain") or sub.get("count_domain")
                sub["count"] = int(detail.get("count") or 0)
                sub["query_key"] = (detail.get("query_snapshot") or {}).get("query_key") or sub.get("query_key")
                sub["parser_version"] = detail.get("parser_version") or sub.get("parser_version")
                sub["confidence"] = detail.get("confidence") or sub.get("confidence")
            section["count"] = sum(int(s.get("count") or 0) for s in section.get("subcategories") or [])
    return catalog


def get_objective_procedure_catalog(db: Session) -> dict[str, Any]:
    from app.services.axiom_catalog_ingest import get_axiom_objectives_catalog

    return get_axiom_objectives_catalog(db)


def default_enabled_objective_ids(catalog: dict[str, Any]) -> list[str]:
    return [
        item["key"]
        for section in catalog.get("sections") or []
        for item in section.get("items") or []
        if item.get("critical")
    ]


def default_enabled_keys(catalog: dict[str, Any]) -> list[str]:
    from app.services.artifact_group_service import default_enabled_keys as _group_defaults

    return _group_defaults(catalog)


# Legacy export for any code still importing CRITICAL_SELECTION_KEYS.
CRITICAL_SELECTION_KEYS: frozenset[str] = frozenset()
