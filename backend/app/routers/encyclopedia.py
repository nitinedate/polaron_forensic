"""Encyclopedia API — BRD artifact catalog."""

from __future__ import annotations

from fastapi import APIRouter, Depends, Query
from sqlalchemy.orm import Session

from app.db.session import get_db
from app.deps import CurrentUser, require_firm_permission
from app.services.encyclopedia_ingest import load_encyclopedia_from_jsonl, search_encyclopedia

router = APIRouter(prefix="/api", tags=["encyclopedia"])


@router.get("/encyclopedia/artifacts")
def list_encyclopedia_artifacts(
    q: str | None = None,
    os: str | None = Query(None, alias="operating_system"),
    category: str | None = None,
    limit: int = 50,
    offset: int = 0,
    db: Session = Depends(get_db),
    current: CurrentUser = Depends(require_firm_permission("artifact:read")),
):
    items = search_encyclopedia(db, q=q, os=os, category=category, limit=limit, offset=offset)
    return {"items": items, "total": len(items), "limit": limit, "offset": offset}


@router.post("/encyclopedia/reload")
def reload_encyclopedia(
    force: bool = False,
    db: Session = Depends(get_db),
    current: CurrentUser = Depends(require_firm_permission("job:run")),
):
    return load_encyclopedia_from_jsonl(db, force=force)


@router.get("/jobs/report/artifact-catalog")
def artifact_catalog(
    platform: str | None = None,
    db: Session = Depends(get_db),
    current: CurrentUser = Depends(require_firm_permission("artifact:read")),
):
    from app.services.artifact_selection_catalog import get_selection_artifact_catalog

    return get_selection_artifact_catalog(db, platform=platform or "Windows")


@router.post("/axiom/sync-report-catalog")
def sync_report_catalog(
    platform: str = "Windows",
    db: Session = Depends(get_db),
    current: CurrentUser = Depends(require_firm_permission("job:run")),
):
    """Add Aetheris report-template artifacts/objectives missing from axiom catalog."""
    from app.services.report_catalog_sync import sync_report_catalog_to_db

    return sync_report_catalog_to_db(db, platform=platform)


@router.post("/axiom/reload")
def reload_axiom_catalog(
    force: bool = False,
    db: Session = Depends(get_db),
    current: CurrentUser = Depends(require_firm_permission("job:run")),
):
    from app.services.axiom_catalog_ingest import load_axiom_catalog_from_files

    return load_axiom_catalog_from_files(db, force=force)
