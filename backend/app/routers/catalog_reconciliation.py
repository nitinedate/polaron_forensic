"""AXIOM query manifest & count reconciliation endpoints.

GET  /api/jobs/{job_id}/axiom/query-manifest          full artifact→query→count→AXIOM→delta table
GET  /api/jobs/{job_id}/axiom/query-manifest.csv      same as CSV (Excel)
GET  /api/jobs/{job_id}/axiom/explain/{artifact_id}   what the number is made of (samples, dirs, dates)
POST /api/jobs/{job_id}/axiom/reference-counts        import AXIOM counts (JSON / CSV / pasted Section B)
POST /api/jobs/{job_id}/axiom/reference-counts/builtin seed the Ex-5 reference for regression checks
"""

from __future__ import annotations

from typing import Any

from fastapi import APIRouter, Body, Depends, HTTPException, Query
from fastapi.responses import Response
from sqlalchemy.orm import Session

from app.deps import CurrentUser, firm_db, require_firm_permission
from app.services.catalog_query_manifest import (
    build_query_manifest,
    explain_artifact,
    import_reference_counts,
    manifest_to_csv,
    seed_reference_counts_from_builtin,
)

router = APIRouter(prefix="/api/jobs", tags=["axiom-reconciliation"])


@router.get("/{job_id}/axiom/query-manifest")
def axiom_query_manifest(
    job_id: str,
    only_gaps: bool = Query(False, description="Return only artifacts whose delta vs AXIOM is non-zero."),
    db: Session = Depends(firm_db),
    current: CurrentUser = Depends(require_firm_permission("job:read")),
) -> dict[str, Any]:
    manifest = build_query_manifest(db, job_id)
    if only_gaps:
        manifest["items"] = [i for i in manifest["items"] if i.get("delta")]
    return manifest


@router.get("/{job_id}/axiom/query-manifest.csv")
def axiom_query_manifest_csv(
    job_id: str,
    db: Session = Depends(firm_db),
    current: CurrentUser = Depends(require_firm_permission("job:read")),
) -> Response:
    manifest = build_query_manifest(db, job_id)
    return Response(
        content=manifest_to_csv(manifest),
        media_type="text/csv",
        headers={"Content-Disposition": f'attachment; filename="axiom_query_manifest_{job_id[:8]}.csv"'},
    )


@router.get("/{job_id}/axiom/explain/{artifact_id}")
def axiom_explain_artifact(
    job_id: str,
    artifact_id: str,
    limit: int = Query(50, ge=1, le=500),
    db: Session = Depends(firm_db),
    current: CurrentUser = Depends(require_firm_permission("job:read")),
) -> dict[str, Any]:
    out = explain_artifact(db, job_id, artifact_id, limit=limit)
    if out.get("error"):
        raise HTTPException(status_code=404, detail=out["error"])
    return out


@router.post("/{job_id}/axiom/reference-counts")
def axiom_import_reference_counts(
    job_id: str,
    payload: Any = Body(
        ...,
        description=(
            "AXIOM reference counts. Accepts a JSON list [{\"artifact\":\"PDF Documents\",\"count\":400}], "
            "a JSON object {\"PDF Documents\":400}, or {\"text\":\"<pasted CSV / Section B lines>\"}."
        ),
    ),
    db: Session = Depends(firm_db),
    current: CurrentUser = Depends(require_firm_permission("job:run")),
) -> dict[str, Any]:
    body = payload
    if isinstance(payload, dict) and "text" in payload and len(payload) <= 2:
        body = payload.get("text")
    result = import_reference_counts(db, job_id, body)
    db.commit()
    return result


@router.post("/{job_id}/axiom/reference-counts/builtin")
def axiom_seed_builtin_reference(
    job_id: str,
    db: Session = Depends(firm_db),
    current: CurrentUser = Depends(require_firm_permission("job:run")),
) -> dict[str, Any]:
    result = seed_reference_counts_from_builtin(db, job_id)
    db.commit()
    return result
