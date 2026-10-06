"""Excel export for artifact catalog and extracted file lists."""

from __future__ import annotations

from io import BytesIO
from typing import Any

from sqlalchemy.orm import Session

from app.db.sql_helpers import execute, fetchall, fetchone


def _artifacts_where(
    db: Session,
    job_id: str,
    *,
    q: str | None = None,
    category: str | None = None,
    catalog_key: str | None = None,
    catalog_section: str | None = None,
) -> tuple[str, dict[str, Any]]:
    params: dict[str, Any] = {"jid": job_id}
    where = "WHERE job_id=:jid"
    if q:
        where += " AND (file_path ILIKE :q OR file_name ILIKE :q)"
        params["q"] = f"%{q}%"
    if category:
        where += " AND encyclopedia_artifact_id ILIKE :cat"
        params["cat"] = f"%{category}%"
    if catalog_key:
        from app.services.artifact_list_queries import list_where_for_catalog_key

        suffix, filter_params = list_where_for_catalog_key(db, job_id, catalog_key)
        if suffix:
            where += suffix
            params.update(filter_params)
        else:
            ax = fetchone(
                db,
                "SELECT artifact_name FROM public.axiom_artifacts WHERE artifact_id=:k",
                {"k": catalog_key},
            )
            if ax:
                where += " AND (file_path ILIKE :an OR file_name ILIKE :an)"
                params["an"] = f"%{ax['artifact_name']}%"
    elif catalog_section:
        from app.services.artifact_list_queries import list_where_for_catalog_section

        suffix, filter_params = list_where_for_catalog_section(db, job_id, catalog_section)
        if suffix:
            where += suffix
            params.update(filter_params)
        else:
            from app.services.artifact_selection_catalog import resolve_job_axiom_platform

            platform = resolve_job_axiom_platform(db, job_id)
            where += """ AND EXISTS (
                SELECT 1 FROM public.axiom_artifacts aa
                WHERE aa.platform = :platform AND aa.category = :section
                  AND (job_artifacts.file_path ILIKE ('%' || aa.artifact_name || '%')
                       OR job_artifacts.file_name ILIKE ('%' || aa.artifact_name || '%'))
            )"""
            params["platform"] = platform
            params["section"] = catalog_section
    return where, params


def build_catalog_export_xlsx(scope: dict[str, Any], *, job_label: str | None = None) -> bytes:
    from openpyxl import Workbook
    from openpyxl.styles import Font

    wb = Workbook()
    ws = wb.active
    ws.title = "Artifacts"
    headers = ["Group", "Artifact", "Count", "In scope"]
    ws.append(headers)
    for cell in ws[1]:
        cell.font = Font(bold=True)

    enabled_keys = set(scope.get("enabled_keys") or [])
    groups = scope.get("groups") or []
    if not groups:
        groups = _groups_from_sections(scope.get("sections") or [], enabled_keys=enabled_keys)

    total_artifacts = 0
    for group in groups:
        group_name = group.get("group_name") or "Other"
        artifacts = group.get("artifacts") or []
        group_count = int(group.get("group_count") or sum(int(a.get("count") or 0) for a in artifacts))
        group_row = ws.max_row + 1
        ws.append([group_name, "", group_count, ""])
        for col in (1, 3):
            ws.cell(row=group_row, column=col).font = Font(bold=True)
        for art in artifacts:
            key = art.get("key") or ""
            in_scope = art.get("enabled") if "enabled" in art else (key in enabled_keys if key else False)
            count = int(art.get("count") or 0)
            total_artifacts += count
            ws.append([
                group_name,
                art.get("label") or key or "",
                count,
                "Yes" if in_scope else "No",
            ])

    # Keep the legacy Artifacts sheet shape stable for downstream consumers while
    # exposing the forensic count contract in a dedicated audit sheet.
    audit = wb.create_sheet("Count Audit")
    audit_headers = [
        "Group", "Artifact", "Count", "Count domain", "Query", "Query status", "Confidence"
    ]
    audit.append(audit_headers)
    for cell in audit[1]:
        cell.font = Font(bold=True)
    for group in groups:
        group_name = group.get("group_name") or "Other"
        for art in group.get("artifacts") or []:
            audit.append([
                group_name,
                art.get("label") or art.get("key") or "",
                int(art.get("count") or 0),
                art.get("count_domain") or "",
                art.get("query_key") or "",
                art.get("query_status") or "",
                art.get("confidence") or "",
            ])

    summary = wb.create_sheet("Summary")
    summary.append(["Job", job_label or ""])
    summary.append(["Platform", scope.get("platform") or ""])
    summary.append(["Groups", len(groups)])
    summary.append(["Artifact rows", sum(len(g.get("artifacts") or []) for g in groups)])
    summary.append(["Sum of artifact counts", total_artifacts])

    _autosize_worksheet(ws)
    _autosize_worksheet(audit)
    _autosize_worksheet(summary)

    buf = BytesIO()
    wb.save(buf)
    return buf.getvalue()


def _groups_from_sections(sections: list[dict[str, Any]], *, enabled_keys: set[str]) -> list[dict[str, Any]]:
    """Fallback when scope.groups is missing — mirror artifact_group_service layout."""
    groups: list[dict[str, Any]] = []
    for section in sections:
        title = section.get("title") or "Other"
        artifacts: list[dict[str, Any]] = []
        for sub in section.get("subcategories") or []:
            key = sub.get("key") or ""
            artifacts.append({
                "key": key,
                "label": sub.get("label") or key,
                "count": int(sub.get("count") or 0),
                "enabled": key in enabled_keys,
                "count_domain": sub.get("count_domain"),
                "query_key": sub.get("query_key"),
                "query_status": sub.get("query_status"),
                "confidence": sub.get("confidence"),
            })
        groups.append({
            "group_name": title,
            "group_count": int(section.get("count") or sum(a["count"] for a in artifacts)),
            "artifacts": artifacts,
        })
    return groups


def build_files_export_xlsx(
    db: Session,
    job_id: str,
    *,
    q: str | None = None,
    category: str | None = None,
    catalog_key: str | None = None,
    catalog_section: str | None = None,
    job_label: str | None = None,
) -> bytes:
    from openpyxl import Workbook

    from app.services.encyclopedia_match import encyclopedia_label_map, ensure_extended_encyclopedia

    ensure_extended_encyclopedia(db)
    labels = encyclopedia_label_map(db)
    where, params = _artifacts_where(
        db,
        job_id,
        q=q,
        category=category,
        catalog_key=catalog_key,
        catalog_section=catalog_section,
    )

    wb = Workbook(write_only=True)
    ws = wb.create_sheet("Extracted artifacts")
    headers = [
        "Title",
        "Source path",
        "Extension",
        "Category ID",
        "Category label",
        "Size (bytes)",
        "Storage URI",
        "Created at",
    ]
    header_row = headers[:]
    ws.append(header_row)

    batch = 5000
    offset = 0
    total = 0
    while True:
        batch_params = {**params, "limit": batch, "offset": offset}
        rows = fetchall(
            db,
            f"""SELECT file_name, file_path, extension, encyclopedia_artifact_id,
                       size_bytes, minio_uri, created_at
                FROM job_artifacts {where}
                ORDER BY file_path
                LIMIT :limit OFFSET :offset""",
            batch_params,
        )
        if not rows:
            break
        for row in rows:
            enc_id = row.get("encyclopedia_artifact_id") or "unknown"
            created = row.get("created_at")
            ws.append([
                row.get("file_name"),
                row.get("file_path"),
                row.get("extension") or "file",
                enc_id,
                labels.get(enc_id, enc_id),
                row.get("size_bytes"),
                row.get("minio_uri"),
                created.isoformat() if hasattr(created, "isoformat") else str(created or ""),
            ])
        total += len(rows)
        offset += len(rows)
        if len(rows) < batch:
            break

    summary = wb.create_sheet("Summary")
    summary.append(["Job", job_label or job_id])
    summary.append(["Exported rows", total])
    if q:
        summary.append(["Search filter", q])
    if category:
        summary.append(["Category filter", category])

    buf = BytesIO()
    wb.save(buf)
    return buf.getvalue()


def _autosize_worksheet(ws, *, max_width: int = 60) -> None:
    from openpyxl.utils import get_column_letter

    for col_idx, column_cells in enumerate(ws.columns, start=1):
        max_len = 0
        for cell in column_cells:
            if cell.value is not None:
                max_len = max(max_len, len(str(cell.value)))
        ws.column_dimensions[get_column_letter(col_idx)].width = min(max_width, max(10, max_len + 2))


def export_filename(job_id: str, kind: str, *, case_name: str | None = None) -> str:
    base = (case_name or job_id[:8]).replace(" ", "_")
    safe = "".join(c if c.isalnum() or c in "-_" else "_" for c in base)
    return f"{safe}_{kind}.xlsx"


def artifact_scope_payload(
    db: Session,
    job_id: str,
    *,
    allow_zero_count: bool = False,
    read_only: bool = False,
    refresh_collectors: bool | None = None,
) -> dict[str, Any]:
    """Artifact catalog + counts + persisted group selection for the Artifacts page."""
    import json

    from app.services.artifact_group_service import resolve_artifact_scope
    from app.services.artifact_selection_catalog import get_selection_artifact_catalog, resolve_job_axiom_platform
    from app.services.axiom_artifact_runner import axiom_inventory_progress

    platform = resolve_job_axiom_platform(db, job_id)
    intake_row = fetchone(
        db,
        "SELECT case_type, report_type, incident_summary FROM case_intake WHERE job_id=:jid",
        {"jid": job_id},
    )
    catalog = get_selection_artifact_catalog(
        db,
        platform=platform,
        job_id=job_id,
        read_only=read_only,
        refresh_collectors=refresh_collectors,
    )
    critical_keys = sorted({
        sub["key"] for section in catalog["sections"] for sub in section["subcategories"] if sub.get("critical")
    })
    row = fetchone(db, "SELECT sections FROM artifact_scope WHERE job_id=:jid", {"jid": job_id})
    stored = row["sections"] if row else []
    if isinstance(stored, str):
        stored = json.loads(stored)
    enabled = stored if isinstance(stored, list) and stored and isinstance(stored[0], str) else []
    template_defaults: list[str] = []
    try:
        from app.services.report_template_service import (
            template_artifact_id_set,
            template_default_artifact_ids,
        )

        report_type = (intake_row or {}).get("report_type")
        if template_artifact_id_set(db, report_type, platform=platform):
            template_defaults = template_default_artifact_ids(db, report_type, platform=platform)
    except Exception:
        template_defaults = []
        try:
            db.rollback()
        except Exception:
            pass
    initial_enabled = enabled or (template_defaults or None)
    resolved = resolve_artifact_scope(
        db,
        job_id,
        catalog,
        stored_enabled=initial_enabled,
        persist=not read_only,
        allow_zero_count=read_only or allow_zero_count,
    )
    if (
        not read_only
        and not allow_zero_count
        and resolved.get("scope_changed")
        and resolved.get("enabled_keys") is not None
    ):
        execute(
            db,
            """INSERT INTO artifact_scope (job_id, sections) VALUES (:jid, CAST(:s AS jsonb))
               ON CONFLICT (job_id) DO UPDATE SET sections=EXCLUDED.sections, updated_at=NOW()""",
            {"jid": job_id, "s": json.dumps(resolved["enabled_keys"])},
        )
        db.flush()
    inventory = axiom_inventory_progress(db, job_id)
    suggestion = None
    try:
        from app.services.investigation_header_service import suggest_investigation_scope

        suggestion = suggest_investigation_scope(
            db,
            job_id,
            case_type=(intake_row or {}).get("case_type"),
            report_type=(intake_row or {}).get("report_type"),
            intake_allegations=(intake_row or {}).get("incident_summary"),
        )
    except Exception:
        suggestion = None
    payload = {
        "enabled_keys": resolved["enabled_keys"],
        "groups": resolved["groups"],
        "sections": catalog["sections"],
        "default_critical_keys": critical_keys,
        "platform": platform,
        "axiom_inventory": inventory,
        "suggested_investigation_scope": suggestion,
    }
    try:
        from app.services.report_template_service import (
            apply_report_template_artifact_defaults,
            get_selected_job_artifacts,
            template_artifact_id_set,
        )

        report_type = (intake_row or {}).get("report_type") if intake_row else None
        template_ids = template_artifact_id_set(db, report_type, platform=platform)
        if template_ids:
            payload = apply_report_template_artifact_defaults(payload, template_ids)
        selected = get_selected_job_artifacts(db, job_id)
        if selected:
            raw = selected.get("artifact_ids") or []
            if isinstance(raw, str):
                raw = json.loads(raw)
            payload["report_saved_artifact_ids"] = list(raw)
            payload["report_artifacts_saved_at"] = (
                selected["saved_at"].isoformat()
                if selected.get("saved_at") and hasattr(selected["saved_at"], "isoformat")
                else selected.get("saved_at")
            )
    except Exception:
        try:
            db.rollback()
        except Exception:
            pass
    return payload


def build_catalog_export_for_job(
    db: Session, job_id: str, *, job_label: str | None = None, authoritative_refresh: bool = True
) -> bytes:
    # Export is an evidential snapshot, not a cache dump. Recompute the report-template
    # collectors immediately before generating XLSX so stale inventory values cannot
    # survive parser/query fixes. Full 634-row inventory remains persisted separately.
    if authoritative_refresh:
        try:
            from app.services.report_catalog_sync import ensure_report_template_artifacts
            from app.services.axiom_artifact_runner import persist_collector_counts
            from app.services.artifact_selection_catalog import resolve_job_axiom_platform
            platform = resolve_job_axiom_platform(db, job_id)
            ensure_report_template_artifacts(db, platform=platform)
            persist_collector_counts(db, job_id, platform=platform, report_only=True)
            db.commit()
        except Exception:
            try:
                db.rollback()
            except Exception:
                pass
            raise
    scope = artifact_scope_payload(db, job_id, allow_zero_count=True, read_only=True)
    catalog_bytes = build_catalog_export_xlsx(scope, job_label=job_label)
    # Enrich workbook with browsable Email & Calendar file rows (content paths, not just counts).
    try:
        from io import BytesIO as _BytesIO

        from openpyxl import load_workbook

        wb = load_workbook(_BytesIO(catalog_bytes))
        summary = wb["Summary"] if "Summary" in wb.sheetnames else wb.create_sheet("Summary")
        summary.append([])
        summary.append([
            "Note",
            "Catalog Count = refreshed per-job collector result. Count domain/query columns identify "
            "whether the value is a file occurrence, parsed artifact record, or another explicit domain. "
            "Email files sheet lists indexed mail-related source files and is not itself an email-message count.",
        ])
        ws = wb.create_sheet("Email files")
        ws.append(["File name", "Source path", "Extension", "Size (bytes)", "Has stored content"])
        rows = fetchall(
            db,
            """SELECT file_name, file_path, extension, size_bytes, minio_uri
               FROM job_artifacts
               WHERE job_id=:jid
                 AND (
                   lower(coalesce(extension,'')) IN ('eml','emlx','msg','.eml','.emlx','.msg')
                   OR lower(file_name) LIKE '%.eml'
                   OR lower(file_name) LIKE '%.emlx'
                   OR lower(file_name) LIKE '%.msg'
                   OR file_path ILIKE '%/Windows Mail/%'
                   OR file_path ILIKE '%Content.Outlook%'
                   OR file_path ILIKE '%.pst'
                   OR file_path ILIKE '%.ost'
                   OR file_path ILIKE '%/Olk/%'
                 )
               ORDER BY size_bytes DESC NULLS LAST
               LIMIT 20000""",
            {"jid": job_id},
        )
        for row in rows:
            ws.append([
                row.get("file_name"),
                row.get("file_path"),
                row.get("extension"),
                row.get("size_bytes"),
                "Yes" if row.get("minio_uri") else "No",
            ])
        summary.append(["Email files exported", len(rows)])
        _autosize_worksheet(ws)
        buf = BytesIO()
        wb.save(buf)
        return buf.getvalue()
    except Exception:
        return catalog_bytes
