"""Image Evidence RAG APIs — selection workspace, repository tree, start processing."""

from __future__ import annotations

import logging
from typing import Any

from fastapi import APIRouter, Depends, File, Form, HTTPException, Query, UploadFile
from pydantic import BaseModel, Field
from sqlalchemy.orm import Session

from app.deps import CurrentUser, firm_db, require_firm_permission, require_firm_permission_released
from app.services import rag_image_evidence as rie
from app.services.rag_processing_profiles import normalize_profile

log = logging.getLogger("rag_image_evidence.api")

router = APIRouter(prefix="/api/rag", tags=["rag-image-evidence"])


class CreateSessionIn(BaseModel):
    case_id: str | None = None
    processing_profile: str | None = "STANDARD"


class ManifestItemIn(BaseModel):
    node_id: str
    parent_node_id: str | None = None
    node_type: str = "image"
    root_label: str | None = None
    relative_path: str
    name: str
    selected: bool = False
    selection_state: str | None = None
    size_bytes: int | None = None
    mime_type: str | None = None
    metadata: dict[str, Any] | None = None


class PutManifestIn(BaseModel):
    items: list[ManifestItemIn] = Field(default_factory=list)
    processing_profile: str | None = None


class StartJobIn(BaseModel):
    processing_profile: str | None = None
    case_id: str | None = None
    # Optional node_id → absolute server path (after upload or known path)
    source_paths: dict[str, str] | None = None


def _schema(current: CurrentUser) -> str:
    schema = getattr(current, "schema_name", None) or ""
    if not schema:
        raise HTTPException(status_code=400, detail={"error": {"code": "no_firm", "message": "Firm schema required"}})
    return schema


@router.get("/profiles")
def get_profiles(current: CurrentUser = Depends(require_firm_permission("job:read"))):
    return {"profiles": rie.profiles_payload()}


@router.post("/selection-sessions")
def create_selection_session(
    body: CreateSessionIn,
    db: Session = Depends(firm_db),
    current: CurrentUser = Depends(require_firm_permission("job:run")),
):
    schema = _schema(current)
    rie.ensure_schema(db, schema)
    try:
        session = rie.create_session(
            db,
            created_by=current.user_id,
            case_id=body.case_id,
            profile=body.processing_profile,
        )
        db.commit()
        return {"session": session}
    except Exception as exc:
        db.rollback()
        raise HTTPException(
            status_code=503,
            detail={
                "error": {
                    "code": "schema_missing",
                    "message": str(exc),
                    "hint": "Apply migrations/029_firm_rag_image_evidence.sql",
                }
            },
        ) from exc


@router.get("/selection-sessions/{session_id}")
def get_selection_session(
    session_id: str,
    db: Session = Depends(firm_db),
    current: CurrentUser = Depends(require_firm_permission("job:read")),
):
    _schema(current)
    session = rie.get_session(db, session_id)
    if not session:
        raise HTTPException(status_code=404, detail={"error": {"code": "not_found", "message": "Session not found"}})
    items = rie.session_artifacts(db, session_id)
    return {"session": session, "artifacts": items}


@router.put("/selection-sessions/{session_id}/manifest")
def put_manifest(
    session_id: str,
    body: PutManifestIn,
    db: Session = Depends(firm_db),
    current: CurrentUser = Depends(require_firm_permission("job:run")),
):
    _schema(current)
    try:
        result = rie.put_manifest(db, session_id, [i.model_dump() for i in body.items])
        if body.processing_profile:
            from app.db.sql_helpers import execute

            execute(
                db,
                "UPDATE rag_selection_sessions SET processing_profile=:p, updated_at=NOW() WHERE id=:id",
                {"p": normalize_profile(body.processing_profile), "id": session_id},
            )
            result["session"] = rie.get_session(db, session_id)
        db.commit()
        return result
    except ValueError as exc:
        db.rollback()
        raise HTTPException(status_code=400, detail={"error": {"code": "manifest_failed", "message": str(exc)}})
    except Exception as exc:
        db.rollback()
        raise HTTPException(status_code=500, detail={"error": {"code": "manifest_failed", "message": str(exc)}})


@router.get("/repository/tree")
def repository_tree(
    parent: str | None = Query(None, description="Optional absolute host path (same as host_path)"),
    drive: str = Query("", description="Drive key e.g. c, d, volumes"),
    path: str = Query("", description="Browse path under drive"),
    host_path: str | None = Query(None, description="Paste any absolute path (Windows/Unix/USB/SSD)"),
    limit: int = Query(500, ge=1, le=2000),
    current: CurrentUser = Depends(require_firm_permission("job:read")),
):
    _schema(current)
    return rie.list_repository_children(
        parent,
        drive=drive,
        browse_path=path,
        host_path=host_path or parent,
        limit=limit,
    )


@router.get("/repository/list-files")
def repository_list_files(
    drive: str = Query("", description="Drive key e.g. c, d, volumes"),
    path: str = Query("", description="Browse path under drive"),
    host_path: str | None = Query(None, description="Absolute host folder to scan recursively"),
    max_files: int = Query(50_000, ge=1, le=50_000),
    max_depth: int = Query(32, ge=1, le=64),
    current: CurrentUser = Depends(require_firm_permission("job:read")),
):
    """Recursive image/PDF inventory for multi-folder Image Evidence selection."""
    _schema(current)
    return rie.list_repository_files(
        drive=drive,
        browse_path=path,
        host_path=host_path,
        max_files=max_files,
        max_depth=max_depth,
    )


@router.post("/selection-sessions/{session_id}/upload")
def upload_selection_files(
    session_id: str,
    files: list[UploadFile] = File(...),
    paths: list[str] | None = Form(None),
    current: CurrentUser = Depends(require_firm_permission_released("job:run")),
):
    """Stage images/PDFs from any browser and append them to the selection manifest."""
    from app.db.session import firm_session
    from app.db.tenant import Scope, TenantContext, set_tenant_context
    from app.services.client_intake import stage_upload_file

    schema = _schema(current)
    with firm_session(schema) as db:
        set_tenant_context(TenantContext(slug=current.tenant, scope=Scope.FIRM, schema_name=schema))
        if not rie.get_session(db, session_id):
            raise HTTPException(status_code=404, detail={"error": {"code": "not_found", "message": "Session not found"}})
    staged: list[dict] = []
    for idx, upload in enumerate(files or []):
        rel = ""
        if paths and idx < len(paths) and paths[idx]:
            rel = paths[idx]
        else:
            rel = getattr(upload, "filename", None) or f"file-{idx}"
        staged.append(
            stage_upload_file(
                namespace=f"rag/{session_id}",
                relative_path=rel,
                src=upload.file,
            )
        )
    try:
        with firm_session(schema) as db:
            set_tenant_context(TenantContext(slug=current.tenant, scope=Scope.FIRM, schema_name=schema))
            result = rie.append_uploaded_items(db, session_id, staged)
        return {
            "items": result.get("items") or [],
            "skipped": result.get("skipped") or [],
            "accepted": result.get("items") or [],
            "session": result.get("session"),
            "message": None,
        }
    except ValueError as exc:
        raise HTTPException(status_code=400, detail={"error": {"code": "upload_failed", "message": str(exc)}}) from exc
    except HTTPException:
        raise
    except Exception as exc:
        log.exception("image evidence upload failed")
        raise HTTPException(status_code=500, detail={"error": {"code": "upload_failed", "message": str(exc)}}) from exc


@router.post("/selection-sessions/{session_id}/start")
def start_processing(
    session_id: str,
    body: StartJobIn,
    db: Session = Depends(firm_db),
    current: CurrentUser = Depends(require_firm_permission("job:run")),
):
    schema = _schema(current)
    rie.ensure_schema(db, schema)
    try:
        result = rie.start_processing_job(
            db,
            session_id=session_id,
            schema_name=schema,
            created_by=current.user_id,
            case_id=body.case_id,
            profile=body.processing_profile,
            source_paths=body.source_paths,
        )
        db.commit()
        return result
    except ValueError as exc:
        db.rollback()
        raise HTTPException(status_code=400, detail={"error": {"code": "start_failed", "message": str(exc)}})
    except Exception as exc:
        db.rollback()
        log.exception("start_processing failed")
        raise HTTPException(status_code=500, detail={"error": {"code": "start_failed", "message": str(exc)}})


@router.get("/jobs/{job_id}/image-assets")
def list_job_image_assets(
    job_id: str,
    db: Session = Depends(firm_db),
    current: CurrentUser = Depends(require_firm_permission("job:read")),
):
    _schema(current)
    from app.db.sql_helpers import fetchall

    rows = fetchall(
        db,
        """SELECT id, job_id, filename, relative_path, root_label, file_size, sha256,
                  mime_type, ocr_status, ocr_confidence, stage_status, thumbnail_uri,
                  left(coalesce(ocr_text, ''), 400) AS ocr_snippet, created_at, updated_at
           FROM rag_image_assets WHERE job_id=:jid
           ORDER BY relative_path NULLS LAST, filename""",
        {"jid": job_id},
    )
    return {"items": rows, "total": len(rows)}
