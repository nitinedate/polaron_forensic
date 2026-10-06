"""Unified logs API for disk, mobile, and vulnerability pipelines."""

from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy.orm import Session

from app.config import get_settings
from app.deps import CurrentUser, firm_db, require_firm
from app.services.rbac_service import user_has_permission
from app.services.unified_logs import list_log_sources, list_unified_logs

router = APIRouter(prefix="/api/logs", tags=["logs"])


def require_logs_access(current: CurrentUser = Depends(require_firm)) -> CurrentUser:
    if not any(
        user_has_permission(current.perms, perm)
        for perm in ("job:read", "scan:read", "vuln:read")
    ):
        raise HTTPException(
            status_code=403,
            detail={"error": {"code": "forbidden", "message": "Missing permission to view logs"}},
        )
    return current


def _include_vuln() -> bool:
    return bool(get_settings().vuln_module_enabled)


@router.get("")
def list_logs(
    source_type: str | None = Query(None, description="all | disk | mobile | vuln"),
    origin: str | None = Query(None, description="all | inhouse | external"),
    level: str | None = Query(None, description="all | error | warning | info | debug"),
    job_id: str | None = None,
    from_ts: str | None = Query(None, alias="from"),
    to_ts: str | None = Query(None, alias="to"),
    q: str | None = None,
    page: int = 1,
    page_size: int = 200,
    db: Session = Depends(firm_db),
    current: CurrentUser = Depends(require_logs_access),
):
    return list_unified_logs(
        db,
        source_type=source_type,
        origin=origin,
        level=level,
        job_id=job_id,
        from_ts=from_ts,
        to_ts=to_ts,
        q=q,
        page=page,
        page_size=page_size,
        include_vuln=_include_vuln(),
    )


@router.get("/sources")
def log_sources(
    source_type: str | None = Query(None),
    origin: str | None = Query(None, description="all | inhouse | external"),
    db: Session = Depends(firm_db),
    current: CurrentUser = Depends(require_logs_access),
):
    items = list_log_sources(
        db,
        source_type=source_type,
        origin=origin,
        include_vuln=_include_vuln(),
    )
    return {"items": items, "total": len(items)}
