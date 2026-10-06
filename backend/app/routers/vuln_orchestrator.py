"""Multi-scanner orchestration and solution-set report APIs."""

from __future__ import annotations

from fastapi import APIRouter, Depends, File, HTTPException, Query, UploadFile
from fastapi.responses import PlainTextResponse, Response
from pydantic import BaseModel
from sqlalchemy.orm import Session

from app.config import get_settings
from app.db.sql_helpers import fetchall
from app.deps import CurrentUser, firm_db, require_firm_permission
from app.services.scan_orchestrator import DEFAULT_PIPELINE
from app.services.gap_assessment_report import export_gap_report, export_merged_gap_report
from app.services.vuln_nessus_parity import compare_nessus_csv
from app.services.vuln_report_export import (
    export_case_csv,
    export_case_summary,
    export_case_xlsx,
    export_service_coverage_csv,
    load_service_coverage,
    import_solution_csv,
)

router = APIRouter(tags=["vuln-orchestrator"])


def _require_vuln_module() -> None:
    if not get_settings().vuln_module_enabled:
        raise HTTPException(status_code=404, detail={"error": {"code": "vuln_disabled", "message": "Vulnerability module is disabled"}})


@router.get("/api/vuln/orchestrator/pipeline")
def get_default_pipeline(current: CurrentUser = Depends(require_firm_permission("scan:read"))):
    _require_vuln_module()
    return {"pipeline": DEFAULT_PIPELINE, "orchestration_enabled": get_settings().vuln_orchestration_enabled}


@router.get("/api/cases/{case_id}/vuln-report.csv")
def export_vuln_report_csv(
    case_id: str,
    db: Session = Depends(firm_db),
    current: CurrentUser = Depends(require_firm_permission("vuln:read")),
):
    _require_vuln_module()
    csv_text = export_case_csv(db, case_id=case_id)
    return PlainTextResponse(
        content=csv_text,
        media_type="text/csv",
        headers={"Content-Disposition": f'attachment; filename="vuln-report-{case_id[:8]}.csv"'},
    )


@router.get("/api/cases/{case_id}/vuln-report.xlsx")
def export_vuln_report_xlsx(
    case_id: str,
    db: Session = Depends(firm_db),
    current: CurrentUser = Depends(require_firm_permission("vuln:read")),
):
    _require_vuln_module()
    data = export_case_xlsx(db, case_id=case_id)
    return Response(
        content=data,
        media_type="application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
        headers={"Content-Disposition": f'attachment; filename="Solution Set-{case_id[:8]}.xlsx"'},
    )


@router.get("/api/cases/{case_id}/vuln-report/summary")
def vuln_report_summary(
    case_id: str,
    db: Session = Depends(firm_db),
    current: CurrentUser = Depends(require_firm_permission("vuln:read")),
):
    _require_vuln_module()
    return export_case_summary(db, case_id=case_id)


@router.get("/api/cases/{case_id}/service-coverage.csv")
def service_coverage_csv(case_id: str, db: Session = Depends(firm_db),
                         current: CurrentUser = Depends(require_firm_permission("vuln:read"))):
    _require_vuln_module()
    return PlainTextResponse(export_service_coverage_csv(db, case_id=case_id), media_type="text/csv",
                             headers={"Content-Disposition": f'attachment; filename="service-coverage-{case_id[:8]}.csv"'})


@router.get("/api/cases/{case_id}/service-coverage")
def service_coverage_json(case_id: str, db: Session = Depends(firm_db),
                         current: CurrentUser = Depends(require_firm_permission("vuln:read"))):
    _require_vuln_module()
    return {"case_id": case_id, "jobs": load_service_coverage(db, case_id=case_id)}


class CsvImportBody(BaseModel):
    csv_text: str


@router.post("/api/cases/{case_id}/vuln-report/import")
def import_vuln_report_csv(
    case_id: str,
    body: CsvImportBody,
    db: Session = Depends(firm_db),
    current: CurrentUser = Depends(require_firm_permission("scan:launch")),
):
    _require_vuln_module()
    return import_solution_csv(db, case_id=case_id, csv_text=body.csv_text)


class NessusParityBody(BaseModel):
    csv_text: str


@router.post("/api/cases/{case_id}/nessus-parity/compare")
def compare_nessus_parity_text(
    case_id: str,
    body: NessusParityBody,
    db: Session = Depends(firm_db),
    current: CurrentUser = Depends(require_firm_permission("vuln:read")),
):
    _require_vuln_module()
    try:
        return compare_nessus_csv(db, case_id=case_id, csv_text=body.csv_text)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail={"error": {"code": "nessus_csv_invalid", "message": str(exc)}}) from exc


@router.post("/api/cases/{case_id}/nessus-parity/compare-file")
async def compare_nessus_parity_file(
    case_id: str,
    file: UploadFile = File(...),
    db: Session = Depends(firm_db),
    current: CurrentUser = Depends(require_firm_permission("vuln:read")),
):
    _require_vuln_module()
    raw = await file.read()
    try:
        text = raw.decode("utf-8-sig")
    except UnicodeDecodeError:
        text = raw.decode("latin-1")
    try:
        return compare_nessus_csv(db, case_id=case_id, csv_text=text)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail={"error": {"code": "nessus_csv_invalid", "message": str(exc)}}) from exc


@router.post("/api/cases/{case_id}/vuln-report/import-file")
async def import_vuln_report_file(
    case_id: str,
    file: UploadFile = File(...),
    db: Session = Depends(firm_db),
    current: CurrentUser = Depends(require_firm_permission("scan:launch")),
):
    _require_vuln_module()
    raw = await file.read()
    try:
        text = raw.decode("utf-8-sig")
    except UnicodeDecodeError:
        text = raw.decode("latin-1")
    return import_solution_csv(db, case_id=case_id, csv_text=text)


@router.get("/api/cases/gap-report/merged.pdf")
def export_merged_gap_report_pdf(
    case_ids: str = Query(
        ...,
        description="Comma-separated case UUIDs (2+). Same findings append IPs; different findings stay separate.",
    ),
    llm: str | None = None,
    db: Session = Depends(firm_db),
    current: CurrentUser = Depends(require_firm_permission("vuln:read")),
):
    _require_vuln_module()
    ids = [p.strip() for p in case_ids.split(",") if p.strip()]
    use_llm = str(llm or "").strip().lower() in {"1", "true", "yes", "on"}
    try:
        data, media_type, filename = export_merged_gap_report(db, ids, fmt="pdf", use_llm=use_llm)
    except ValueError as exc:
        raise HTTPException(
            status_code=400,
            detail={"error": {"code": "merge_invalid", "message": str(exc)}},
        ) from exc
    except Exception as exc:
        raise HTTPException(
            status_code=500,
            detail={"error": {"code": "export_failed", "message": str(exc)}},
        ) from exc
    return Response(
        content=data,
        media_type=media_type,
        headers={"Content-Disposition": f'attachment; filename="{filename}"'},
    )


@router.get("/api/cases/{case_id}/gap-report.pdf")
def export_gap_report_pdf(
    case_id: str,
    llm: str | None = None,
    db: Session = Depends(firm_db),
    current: CurrentUser = Depends(require_firm_permission("vuln:read")),
):
    _require_vuln_module()
    use_llm = str(llm or "").strip().lower() in {"1", "true", "yes", "on"}
    try:
        data, media_type, filename = export_gap_report(db, case_id, fmt="pdf", use_llm=use_llm)
    except ValueError as exc:
        raise HTTPException(status_code=404, detail={"error": {"code": "not_found", "message": str(exc)}}) from exc
    except Exception as exc:
        raise HTTPException(
            status_code=500,
            detail={"error": {"code": "export_failed", "message": str(exc)}},
        ) from exc
    return Response(
        content=data,
        media_type=media_type,
        headers={"Content-Disposition": f'attachment; filename="{filename}"'},
    )


@router.get("/api/cases/{case_id}/gap-report.docx")
def export_gap_report_docx(
    case_id: str,
    llm: str | None = None,
    db: Session = Depends(firm_db),
    current: CurrentUser = Depends(require_firm_permission("vuln:read")),
):
    _require_vuln_module()
    use_llm = str(llm or "").strip().lower() in {"1", "true", "yes", "on"}
    try:
        data, media_type, filename = export_gap_report(db, case_id, fmt="docx", use_llm=use_llm)
    except ValueError as exc:
        raise HTTPException(status_code=404, detail={"error": {"code": "not_found", "message": str(exc)}}) from exc
    except Exception as exc:
        raise HTTPException(
            status_code=500,
            detail={"error": {"code": "export_failed", "message": str(exc)}},
        ) from exc
    return Response(
        content=data,
        media_type=media_type,
        headers={"Content-Disposition": f'attachment; filename="{filename}"'},
    )


@router.get("/api/vuln/scan-jobs/{job_id}/engine-runs")
def list_engine_runs(
    job_id: str,
    db: Session = Depends(firm_db),
    current: CurrentUser = Depends(require_firm_permission("scan:read")),
):
    _require_vuln_module()
    rows = fetchall(
        db,
        """SELECT engine, role, status, findings_count, error, started_at, completed_at, metadata_json
           FROM vuln_scan_engine_runs WHERE scan_job_id = CAST(:jid AS uuid) ORDER BY created_at""",
        {"jid": job_id},
    )
    return {"items": [dict(r) for r in rows]}
