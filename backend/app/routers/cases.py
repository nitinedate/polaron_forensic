"""Cases API — workspace records for vuln scans and forensic grouping."""

from __future__ import annotations

import uuid
from datetime import date, datetime, timedelta, timezone
from typing import Any
from zoneinfo import ZoneInfo

from fastapi import APIRouter, Depends, HTTPException, Query
from pydantic import BaseModel
from sqlalchemy.orm import Session

from app.db.session import apply_firm_search_path
from app.db.sql_helpers import execute, fetchall, fetchone
from app.deps import CurrentUser, firm_db, require_firm
from app.services.case_delete import delete_case_cascade
from app.services.rbac_service import user_has_permission

router = APIRouter(prefix="/api/cases", tags=["cases"])

DEFAULT_WORKSPACE_ID = "00000000-0000-4000-8000-000000000001"
_IST = ZoneInfo("Asia/Kolkata")


def _ist_today() -> date:
    return datetime.now(_IST).date()


def gap_merge_date_window(from_date: str | None, *, today: date | None = None) -> tuple[date, date]:
    """Inclusive From..To window in Asia/Kolkata. To is always today."""
    end = today or _ist_today()
    raw = str(from_date or "").strip()
    if not raw:
        start = end - timedelta(days=1)
    else:
        try:
            start = date.fromisoformat(raw[:10])
        except ValueError as exc:
            raise HTTPException(
                status_code=400,
                detail={"error": {"code": "invalid_date", "message": "from_date must be YYYY-MM-DD"}},
            ) from exc
    if start > end:
        start = end
    return start, end


_MONTH_ABBR = (
    "Jan", "Feb", "Mar", "Apr", "May", "Jun",
    "Jul", "Aug", "Sep", "Oct", "Nov", "Dec",
)


def _gap_day_label(created_ist: date | None, today: date) -> str:
    if created_ist is None:
        return "unknown"
    if created_ist == today:
        return "today"
    if created_ist == today - timedelta(days=1):
        return "yesterday"
    return f"{created_ist.day:02d} {_MONTH_ABBR[created_ist.month - 1]} {created_ist.year}"


class CaseCreateBody(BaseModel):
    title: str | None = None
    number: str | None = None
    job_id: str | None = None
    classification: str | None = None
    timezone: str = "UTC"


class CaseUpdateBody(BaseModel):
    title: str | None = None
    number: str | None = None
    status: str | None = None
    classification: str | None = None
    timezone: str | None = None
    authorization_notes: str | None = None


def _require_case_read(current: CurrentUser = Depends(require_firm)) -> CurrentUser:
    if not (
        user_has_permission(current.perms, "job:read")
        or user_has_permission(current.perms, "scan:read")
        or user_has_permission(current.perms, "vuln:read")
    ):
        raise HTTPException(
            status_code=403,
            detail={"error": {"code": "forbidden", "message": "Missing permission to read cases"}},
        )
    return current


def _require_case_write(current: CurrentUser = Depends(require_firm)) -> CurrentUser:
    if not (
        user_has_permission(current.perms, "job:run")
        or user_has_permission(current.perms, "scan:launch")
        or user_has_permission(current.perms, "case:manage")
    ):
        raise HTTPException(
            status_code=403,
            detail={"error": {"code": "forbidden", "message": "Missing permission to manage cases"}},
        )
    return current


def _row_to_case(row: dict[str, Any]) -> dict[str, Any]:
    return {
        "id": str(row["id"]),
        "job_id": str(row["job_id"]) if row.get("job_id") else None,
        "number": row.get("number"),
        "title": row.get("title"),
        "status": row.get("status") or "open",
        "classification": row.get("classification"),
        "timezone": row.get("timezone") or "UTC",
        "owner_id": str(row["owner_id"]) if row.get("owner_id") else None,
        "authorization_notes": row.get("authorization_notes"),
        "created_at": row["created_at"].isoformat() if hasattr(row["created_at"], "isoformat") else str(row["created_at"]),
    }


def _ensure_cases_table(db: Session, schema_name: str | None) -> None:
    """Create firm.cases if this isolated DB never got apply_firm_cases."""
    apply_firm_search_path(db, schema_name)
    try:
        fetchone(db, "SELECT 1 FROM cases LIMIT 1")
        return
    except Exception:
        db.rollback()
    apply_firm_search_path(db, schema_name)
    execute(
        db,
        """CREATE TABLE IF NOT EXISTS cases (
            id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
            job_id UUID,
            number TEXT,
            title TEXT NOT NULL DEFAULT 'Untitled case',
            status TEXT NOT NULL DEFAULT 'open',
            classification TEXT,
            timezone TEXT NOT NULL DEFAULT 'UTC',
            owner_id UUID,
            authorization_notes TEXT,
            created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
            updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
        )""",
    )
    try:
        execute(db, "ALTER TABLE cases ADD COLUMN IF NOT EXISTS gap_site_json JSONB DEFAULT '{}'::jsonb")
    except Exception:
        db.rollback()
        apply_firm_search_path(db, schema_name)
    db.commit()
    apply_firm_search_path(db, schema_name)


def _ensure_default_workspace(db: Session, schema_name: str | None) -> None:
    _ensure_cases_table(db, schema_name)
    existing = fetchone(
        db,
        "SELECT id FROM cases WHERE id = CAST(:id AS uuid)",
        {"id": DEFAULT_WORKSPACE_ID},
    )
    if existing:
        return
    execute(
        db,
        """INSERT INTO cases (id, title, status, timezone, created_at, updated_at)
           VALUES (CAST(:id AS uuid), 'Default workspace', 'open', 'UTC', NOW(), NOW())""",
        {"id": DEFAULT_WORKSPACE_ID},
    )
    db.commit()
    apply_firm_search_path(db, schema_name)


@router.get("")
def list_cases(
    page: int = 1,
    page_size: int = 20,
    status: str | None = None,
    db: Session = Depends(firm_db),
    current: CurrentUser = Depends(_require_case_read),
):
    _ensure_default_workspace(db, current.schema_name)
    page = max(1, page)
    page_size = min(max(1, page_size), 100)
    offset = (page - 1) * page_size
    where = "TRUE"
    params: dict[str, Any] = {"lim": page_size, "off": offset}
    if status:
        where = "status = :status"
        params["status"] = status
    total = fetchone(db, f"SELECT COUNT(*) AS c FROM cases WHERE {where}", params)
    rows = fetchall(
        db,
        f"""SELECT * FROM cases WHERE {where}
            ORDER BY created_at DESC LIMIT :lim OFFSET :off""",
        params,
    )
    return {
        "items": [_row_to_case(r) for r in rows],
        "total": int((total or {}).get("c") or 0),
        "page": page,
        "page_size": page_size,
    }


@router.get("/gap-merge-candidates")
def list_gap_merge_candidates(
    from_date: str | None = Query(
        default=None,
        description="Inclusive start date YYYY-MM-DD (Asia/Kolkata). Defaults to yesterday. To is always today.",
    ),
    db: Session = Depends(firm_db),
    current: CurrentUser = Depends(_require_case_read),
):
    """
    Cases eligible for Gap Assessment merge:
    - gap_site_json is present and not empty
    - created between from_date and today (Asia/Kolkata calendar)
    - current-day cases listed first
    """
    from app.services.gap_assessment_report import ensure_gap_site_column, _parse_json_field

    start, end = gap_merge_date_window(from_date)
    _ensure_default_workspace(db, current.schema_name)
    ensure_gap_site_column(db)
    apply_firm_search_path(db, current.schema_name)

    rows = fetchall(
        db,
        """
        SELECT c.*,
               (c.created_at AT TIME ZONE 'Asia/Kolkata')::date AS created_ist_date,
               ((c.created_at AT TIME ZONE 'Asia/Kolkata')::date)
                 = ((NOW() AT TIME ZONE 'Asia/Kolkata')::date) AS is_today
        FROM cases c
        WHERE c.gap_site_json IS NOT NULL
          AND jsonb_typeof(c.gap_site_json) = 'object'
          AND c.gap_site_json <> '{}'::jsonb
          AND (c.created_at AT TIME ZONE 'Asia/Kolkata')::date >= CAST(:from_d AS date)
          AND (c.created_at AT TIME ZONE 'Asia/Kolkata')::date <= CAST(:to_d AS date)
        ORDER BY is_today DESC, c.created_at DESC
        LIMIT 200
        """,
        {"from_d": start.isoformat(), "to_d": end.isoformat()},
    )

    detail_keys = (
        "client_name",
        "branch_locations",
        "contact_person",
        "date_of_visit",
        "author",
        "document_version",
        "num_endpoints",
        "geographic_locations",
    )
    items: list[dict[str, Any]] = []
    for row in rows:
        site = _parse_json_field(row.get("gap_site_json"))
        # Extra guard: object must have at least one non-empty string value.
        if not any(str(v).strip() for v in site.values() if not isinstance(v, (dict, list))):
            if not any(
                isinstance(v, dict) and any(str(x).strip() for x in v.values())
                for v in site.values()
            ):
                continue
        case = _row_to_case(row)
        details = {k: site.get(k) for k in detail_keys if str(site.get(k) or "").strip()}
        created_ist = row.get("created_ist_date")
        if isinstance(created_ist, datetime):
            created_ist = created_ist.date()
        elif isinstance(created_ist, str):
            try:
                created_ist = date.fromisoformat(created_ist[:10])
            except ValueError:
                created_ist = None
        items.append(
            {
                **case,
                "day_label": _gap_day_label(created_ist if isinstance(created_ist, date) else None, end),
                "gap_details": details,
                "has_gap_site": True,
            }
        )
    return {
        "items": items,
        "total": len(items),
        "from_date": start.isoformat(),
        "to_date": end.isoformat(),
    }


@router.post("")
def create_case(
    body: CaseCreateBody,
    db: Session = Depends(firm_db),
    current: CurrentUser = Depends(_require_case_write),
):
    title = (body.title or "").strip() or "Untitled case"
    case_id = str(uuid.uuid4())
    _ensure_cases_table(db, current.schema_name)
    apply_firm_search_path(db, current.schema_name)
    execute(
        db,
        """INSERT INTO cases
           (id, job_id, number, title, status, classification, timezone, owner_id, created_at, updated_at)
           VALUES
           (CAST(:id AS uuid), CAST(:job_id AS uuid), :number, :title, 'open', :classification, :timezone,
            CAST(:owner AS uuid), NOW(), NOW())""",
        {
            "id": case_id,
            "job_id": body.job_id if body.job_id else None,
            "number": body.number,
            "title": title,
            "classification": body.classification,
            "timezone": body.timezone or "UTC",
            "owner": current.user_id,
        },
    )
    db.commit()
    apply_firm_search_path(db, current.schema_name)
    row = fetchone(db, "SELECT * FROM cases WHERE id = CAST(:id AS uuid)", {"id": case_id})
    return _row_to_case(row or {"id": case_id, "title": title, "status": "open", "timezone": body.timezone or "UTC", "created_at": datetime.now(timezone.utc)})


@router.get("/{case_id}")
def get_case(
    case_id: str,
    db: Session = Depends(firm_db),
    current: CurrentUser = Depends(_require_case_read),
):
    apply_firm_search_path(db, current.schema_name)
    row = fetchone(db, "SELECT * FROM cases WHERE id = CAST(:id AS uuid)", {"id": case_id})
    if not row:
        raise HTTPException(status_code=404, detail={"error": {"code": "not_found", "message": "Case not found"}})
    return _row_to_case(row)


@router.patch("/{case_id}")
def update_case(
    case_id: str,
    body: CaseUpdateBody,
    db: Session = Depends(firm_db),
    current: CurrentUser = Depends(_require_case_write),
):
    apply_firm_search_path(db, current.schema_name)
    row = fetchone(db, "SELECT id FROM cases WHERE id = CAST(:id AS uuid)", {"id": case_id})
    if not row:
        raise HTTPException(status_code=404, detail={"error": {"code": "not_found", "message": "Case not found"}})
    fields = []
    params: dict[str, Any] = {"id": case_id}
    for key in ("title", "number", "status", "classification", "timezone", "authorization_notes"):
        val = getattr(body, key)
        if val is not None:
            fields.append(f"{key} = :{key}")
            params[key] = val
    if not fields:
        return get_case(case_id, db, current)
    fields.append("updated_at = NOW()")
    execute(db, f"UPDATE cases SET {', '.join(fields)} WHERE id = CAST(:id AS uuid)", params)
    db.commit()
    apply_firm_search_path(db, current.schema_name)
    return get_case(case_id, db, current)


@router.delete("/{case_id}")
def delete_case(
    case_id: str,
    db: Session = Depends(firm_db),
    current: CurrentUser = Depends(_require_case_write),
):
    """Delete a case and its scan jobs, including queued/processing/running scans."""
    apply_firm_search_path(db, current.schema_name)
    try:
        result = delete_case_cascade(db, case_id)
    except LookupError:
        raise HTTPException(status_code=404, detail={"error": {"code": "not_found", "message": "Case not found"}})
    except ValueError:
        raise HTTPException(
            status_code=409,
            detail={
                "error": {
                    "code": "default_workspace",
                    "message": "The default workspace cannot be deleted.",
                }
            },
        )
    db.commit()
    apply_firm_search_path(db, current.schema_name)
    return {"ok": True, **result}


@router.get("/{case_id}/gap-intake")
def get_gap_intake(
    case_id: str,
    db: Session = Depends(firm_db),
    current: CurrentUser = Depends(_require_case_read),
):
    from app.services.gap_assessment_report import load_gap_site

    row = fetchone(db, "SELECT id FROM cases WHERE id = CAST(:id AS uuid)", {"id": case_id})
    if not row:
        raise HTTPException(status_code=404, detail={"error": {"code": "not_found", "message": "Case not found"}})
    return load_gap_site(db, case_id)


class GapSiteBody(BaseModel):
    client_name: str | None = None
    branch_locations: str | None = None
    contact_person: str | None = None
    geographic_locations: str | None = None
    num_offices: str | None = None
    num_endpoints: str | None = None
    operating_systems: dict[str, str] | None = None
    data_centers: str | None = None
    critical_servers: str | None = None
    critical_devices: str | None = None
    web_apps: str | None = None
    mobile_apps: str | None = None
    firewall: dict[str, str] | None = None
    internet: dict[str, str] | None = None
    nac: str | None = None
    antivirus: str | None = None
    backup_storage: str | None = None
    author: str | None = None
    document_version: str | None = None
    date_of_visit: str | None = None
    introduction: str | None = None
    key_contacts: list[dict[str, str]] | None = None


@router.put("/{case_id}/gap-intake")
def put_gap_intake(
    case_id: str,
    body: GapSiteBody,
    db: Session = Depends(firm_db),
    current: CurrentUser = Depends(_require_case_write),
):
    from app.db.session import apply_firm_search_path
    from app.services.gap_assessment_report import load_gap_site, save_gap_site

    row = fetchone(db, "SELECT id FROM cases WHERE id = CAST(:id AS uuid)", {"id": case_id})
    if not row:
        raise HTTPException(status_code=404, detail={"error": {"code": "not_found", "message": "Case not found"}})
    existing = load_gap_site(db, case_id)
    patch = body.model_dump(exclude_unset=True)
    existing.update({k: v for k, v in patch.items() if v is not None})
    saved = save_gap_site(db, case_id, existing)
    apply_firm_search_path(db, current.schema_name)
    return saved


@router.get("/{case_id}/intake")
def case_intake(case_id: str, current: CurrentUser = Depends(_require_case_read)):
    return {
        "case_id": case_id,
        "report_ready": False,
        "missing_fields": ["subjects"],
        "updated_at": datetime.now(timezone.utc).isoformat(),
    }


@router.get("/{case_id}/members")
def case_members(case_id: str, current: CurrentUser = Depends(_require_case_read)):
    return []


@router.get("/{case_id}/chain-of-custody")
def chain_of_custody(case_id: str, current: CurrentUser = Depends(_require_case_read)):
    return []


@router.get("/{case_id}/audit")
def case_audit(
    case_id: str,
    page: int = 1,
    page_size: int = 20,
    current: CurrentUser = Depends(_require_case_read),
):
    return {"items": [], "total": 0, "page": page, "page_size": page_size}
