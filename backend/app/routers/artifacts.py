"""Job artifacts API — maps job_artifacts to frontend Artifact shape."""

from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException, Query
from fastapi.responses import Response, StreamingResponse
from sqlalchemy.orm import Session

from app.db.sql_helpers import fetchall, fetchone
from app.deps import CurrentUser, firm_db, require_firm_permission

router = APIRouter(prefix="/api/jobs", tags=["artifacts"])


def _require_artifact_job(db,job_id):
    if not fetchone(db,"SELECT id FROM jobs WHERE id=:jid",{"jid":job_id}):
        raise HTTPException(status_code=404,detail="Job not found")


@router.get("/{job_id}/priority-evidence")
def priority_evidence(job_id: str, family: str = "whatsapp_messages", page: int = Query(1,ge=1),
                     page_size: int = Query(50,ge=1,le=200), db: Session = Depends(firm_db),
                     current: CurrentUser = Depends(require_firm_permission("artifact:read"))):
    from app.services.forensic_priority_evidence import priority_evidence_page
    _require_artifact_job(db,job_id)
    try:
        return priority_evidence_page(db,job_id,family=family,page=page,page_size=page_size)
    except ValueError as exc:
        raise HTTPException(status_code=422,detail=str(exc)) from exc


@router.get("/{job_id}/media-observations")
def media_observations(job_id: str, page: int = Query(1,ge=1), page_size: int = Query(50,ge=1,le=200),
                      flagged_only: bool = True, db: Session = Depends(firm_db),
                      current: CurrentUser = Depends(require_firm_permission("artifact:read"))):
    from app.services.forensic_media_review import media_observations_page
    _require_artifact_job(db,job_id)
    return media_observations_page(db,job_id,page=page,page_size=page_size,flagged_only=flagged_only)


@router.get('/{job_id}/suspicious-activity')
def suspicious_activity(job_id: str, page: int = Query(1, ge=1), page_size: int = Query(50, ge=1, le=200),
                        db: Session = Depends(firm_db), current: CurrentUser = Depends(require_firm_permission('artifact:read'))):
    from app.services.suspicious_activity import suspicious_activity_page
    _require_artifact_job(db,job_id)
    return suspicious_activity_page(db,job_id,page=page,page_size=page_size)


@router.get("/{job_id}/media-observations/report")
def media_observations_report(job_id: str, db: Session = Depends(firm_db),
                              current: CurrentUser = Depends(require_firm_permission("artifact:read"))):
    from app.services.forensic_media_review import build_media_observations_markdown
    _require_artifact_job(db,job_id)
    content = build_media_observations_markdown(db,job_id)
    return Response(content or "No source-linked image/video review observations have been recorded.",
                    media_type="text/markdown",headers={"Content-Disposition":'attachment; filename="suspicious-activity-observations.md"'})


@router.get("/{job_id}/media-observations/{artifact_id}/frames/{frame_index}")
def media_observation_frame(job_id: str, artifact_id: str, frame_index: int,
                           db: Session = Depends(firm_db),
                           current: CurrentUser = Depends(require_firm_permission("artifact:read"))):
    import base64
    import hashlib
    from app.services.storage import get_bytes
    _require_artifact_job(db,job_id)
    row = fetchone(db,"SELECT details FROM forensic_media_observations WHERE job_id=:jid AND job_artifact_id=:aid",
                   {"jid":job_id,"aid":artifact_id})
    frames = (row["details"] or {}).get("frames",[]) if row else []
    if frame_index<0 or frame_index>=len(frames):
        raise HTTPException(status_code=404,detail="Evidence frame not found")
    frame = frames[frame_index]
    data = get_bytes(frame["derived_frame_uri"])
    if not data or hashlib.sha256(data).hexdigest()!=frame["frame_sha256"]:
        raise HTTPException(status_code=409,detail="Derived evidence frame hash verification failed")
    return {"data_url":"data:image/png;base64,"+base64.b64encode(data).decode("ascii"),
            "sha256":frame["frame_sha256"],"timestamp_seconds":frame.get("timestamp_seconds")}


def _artifact_row(row: dict, labels: dict[str, str] | None = None) -> dict:
    from app.services.deleted_evidence import title_with_deleted_date

    created = row["created_at"]
    enc_id = row.get("encyclopedia_artifact_id") or "unknown"
    labels = labels or {}
    meta = row.get("metadata") or {}
    if not isinstance(meta, dict):
        meta = {}
    else:
        meta = dict(meta)
    try:
        from app.services.artifact_review import review_row

        review = review_row({**row, "metadata": meta})
        if review.get("flagged"):
            meta["review"] = review
    except Exception:
        pass
    display_name = meta.get("original_name") or row.get("file_name")
    title = title_with_deleted_date(display_name, meta)
    deleted_at = meta.get("deleted_at")
    return {
        "id": str(row["id"]),
        "job_id": str(row["job_id"]),
        "file_id": None,
        "parent_artifact_id": None,
        "artifact_type": row.get("extension") or "file",
        "axiom_category": enc_id,
        "axiom_category_label": labels.get(enc_id, enc_id),
        "axiom_sub_category": None,
        "title": title,
        "file_name": row.get("file_name") or display_name,
        "source_path": row.get("file_path"),
        "size_bytes": row.get("size_bytes"),
        "extension": row.get("extension"),
        "artifact_datetime": deleted_at,
        "preview_uri": None,
        "storage_uri": row.get("minio_uri"),
        "metadata": meta,
        "tags": (["deleted"] if meta.get("is_deleted") or deleted_at else []) + (["suspicious_activity"] if meta.get('suspicious_activity') else []),
        "examiner_comment": meta.get('suspicious_activity_description') or ((meta.get("media_review") or {}).get("description")),
        "parser_version": None,
        "confidence": None,
        "created_at": created.isoformat() if hasattr(created, "isoformat") else str(created),
    }


@router.get("/{job_id}/artifact-sections")
def artifact_sections(
    job_id: str,
    refresh_rag: bool = Query(False, description="Also write section summaries into rag_chunks"),
    db: Session = Depends(firm_db),
    current: CurrentUser = Depends(require_firm_permission("artifact:read")),
):
    """Axiom-style B. ARTIFACTS sections (Connected Devices, Documents, …)."""
    from app.services.artifact_sections import (
        build_job_artifact_sections,
        ensure_section_rag_chunks,
        format_sections_markdown,
    )

    inventory = build_job_artifact_sections(db, job_id)
    if refresh_rag:
        ensure_section_rag_chunks(db, job_id, inventory)
        db.commit()
    return {
        **inventory,
        "markdown": format_sections_markdown(inventory),
    }


@router.get("/{job_id}/artifact-catalog/export")
def export_artifact_catalog(
    job_id: str,
    db: Session = Depends(firm_db),
    current: CurrentUser = Depends(require_firm_permission("artifact:read")),
):
    from app.services.artifact_export import build_catalog_export_for_job, export_filename

    job = fetchone(
        db,
        """SELECT j.id, c.title AS case_title FROM jobs j
           LEFT JOIN forensic_cases c ON c.id = j.case_id
           WHERE j.id=:id""",
        {"id": job_id},
    )
    if not job:
        raise HTTPException(status_code=404, detail={"error": {"code": "not_found", "message": "Job not found"}})
    case_title = job.get("case_title")
    content = build_catalog_export_for_job(db, job_id, job_label=case_title or str(job_id))
    filename = export_filename(job_id, "artifacts", case_name=case_title)
    return Response(
        content=content,
        media_type="application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
        headers={"Content-Disposition": f'attachment; filename="{filename}"'},
    )


@router.get("/{job_id}/artifacts/export")
def export_artifacts(
    job_id: str,
    q: str | None = None,
    category: str | None = None,
    catalog_key: str | None = None,
    catalog_section: str | None = None,
    db: Session = Depends(firm_db),
    current: CurrentUser = Depends(require_firm_permission("artifact:read")),
):
    from app.services.artifact_export import build_files_export_xlsx, export_filename

    job = fetchone(
        db,
        """SELECT j.id, c.title AS case_title FROM jobs j
           LEFT JOIN forensic_cases c ON c.id = j.case_id
           WHERE j.id=:id""",
        {"id": job_id},
    )
    if not job:
        raise HTTPException(status_code=404, detail={"error": {"code": "not_found", "message": "Job not found"}})
    case_title = job.get("case_title")
    content = build_files_export_xlsx(
        db,
        job_id,
        q=q,
        category=category,
        catalog_key=catalog_key,
        catalog_section=catalog_section,
        job_label=case_title or str(job_id),
    )
    filename = export_filename(job_id, "extracted_artifacts", case_name=case_title)
    return Response(
        content=content,
        media_type="application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
        headers={"Content-Disposition": f'attachment; filename="{filename}"'},
    )


@router.get("/{job_id}/artifacts/evidence-coverage")
def evidence_coverage(
    job_id: str,
    db: Session = Depends(firm_db),
    current: CurrentUser = Depends(require_firm_permission("artifact:read")),
):
    """Summary of all saved evidences — extensions, extensionless, tiny, unclassified."""
    job = fetchone(db, "SELECT id FROM jobs WHERE id=:id", {"id": job_id})
    if not job:
        raise HTTPException(status_code=404, detail={"error": {"code": "not_found", "message": "Job not found"}})
    from app.services.evidence_coverage import build_evidence_coverage

    return build_evidence_coverage(db, job_id)


@router.get("/{job_id}/artifacts")
def list_artifacts(
    job_id: str,
    page: int = 1,
    page_size: int = 20,
    q: str | None = None,
    category: str | None = None,
    catalog_key: str | None = None,
    catalog_section: str | None = None,
    family: str | None = Query(
        None,
        description="Mobile board family key (deleted_photos, whatsapp_messages, …) — lists all matching files",
    ),
    scope: str | None = Query(
        None,
        description="all = every saved file; unclassified = not mapped to catalog; extensionless = no/empty extension",
    ),
    group_by: str | None = Query(
        None,
        description="person | conversation | album | flat — person/group identity (default for chats), per-chat, or media album",
    ),
    group_id: str | None = Query(
        None,
        description="person_id, conversation_id, or album_id — return full thread/files inside that group",
    ),
    message_filter: str | None = Query(
        None,
        description="When viewing a person/conversation thread: all | current | deleted | media | calls",
    ),
    file_filter: str | None = Query(
        None,
        description="File forensics tabs: all | deleted | photos | videos | documents | extensionless | anomalous | modified | with_dates",
    ),
    db: Session = Depends(firm_db),
    current: CurrentUser = Depends(require_firm_permission("artifact:read")),
):
    from app.services.evidence_browse_indexes import ensure_evidence_browse_indexes

    ensure_evidence_browse_indexes(db)

    scope_norm = (scope or "").strip().lower()
    family_norm = (family or "").strip().lower() or None
    group_id_norm = (group_id or "").strip() or None
    message_filter_norm = (message_filter or "").strip().lower() or None
    file_filter_norm = (file_filter or "").strip().lower() or None

    # Messaging / chat board families: prefer virtual evidence rows (parsed messages +
    # chat DBs) instead of dumping every path under com.whatsapp (APK/ART junk).
    if family_norm and scope_norm not in {"all", "unclassified", "extensionless", "tiny"}:
        from app.services.artifact_family_browse import (
            family_evidence_artifact_name,
            family_prefers_deleted_only,
            filter_evidence_rows_for_family,
        )
        from app.services.artifact_evidence_browse import list_evidence_items
        from app.services.artifact_group_browse import (
            apply_family_grouping,
            person_browse_evidence_names_for_family,
            resolve_group_mode,
        )

        evidence_name = family_evidence_artifact_name(family_norm)
        if family_norm in {"whatsapp_messages", "whatsapp_chats", "whatsapp_deleted_messages"}:
            from app.services.whatsapp_evidence_browse import list_whatsapp_evidence

            normalized = list_whatsapp_evidence(
                db, job_id, family=family_norm, page=page, page_size=page_size,
                group_by=resolve_group_mode(family_norm, group_by), group_id=group_id_norm,
                message_filter=message_filter_norm, q=q,
            )
            if normalized is not None:
                return normalized
        if evidence_name:
            from app.services.artifact_family_browse import (
                no_chat_data_notice,
                strip_runtime_junk,
            )

            group_mode_preview = resolve_group_mode(family_norm, group_by)
            deleted_only = family_prefers_deleted_only(family_norm)
            page_n = max(int(page or 1), 1)
            size_n = max(min(int(page_size or 20), 8000 if group_id_norm else 200), 1)

            # Instant reopen / fast first paint for Deleted Messages Names list.
            # Never fall through to the 8k-message wide extract (that timed out → empty UI).
            if (
                deleted_only
                and group_mode_preview == "person"
                and not group_id_norm
                and not (q or "").strip()
            ):
                from app.services.artifact_evidence_browse import (
                    _load_browse_cache,
                    _whatsapp_deleted_person_rows,
                )

                persons_cached = _load_browse_cache(db, job_id, "wa_deleted_persons_v14")
                if not persons_cached:
                    try:
                        persons_cached = _whatsapp_deleted_person_rows(db, job_id)
                    except Exception:
                        persons_cached = []
                persons_cached = list(persons_cached or [])
                if not persons_cached:
                    notice = no_chat_data_notice(family_norm, job_id, db=db)
                    return {
                        "items": [notice] if notice else [],
                        "total": 1 if notice else 0,
                        "page": page_n,
                        "page_size": size_n,
                        "evidence_domain": "person",
                        "evidence_label": evidence_name,
                        "group_by": "person",
                        "group_id": None,
                        "message_filter": "all",
                        "thread_summary": None,
                    }
                total = len(persons_cached)
                start = (page_n - 1) * size_n
                return {
                    "items": persons_cached[start : start + size_n],
                    "total": total,
                    "page": page_n,
                    "page_size": size_n,
                    "evidence_domain": "person",
                    "evidence_label": evidence_name,
                    "group_by": "person",
                    "group_id": None,
                    "message_filter": "all",
                    "thread_summary": None,
                }

            want_sessions = (
                group_mode_preview == "person"
                and not group_id_norm
                and not deleted_only
            )
            # Deleted boards + person threads need a wide message window (then page
            # after group/filter). Live contact lists use sessions_only + source page.
            wide_person_fetch = group_mode_preview == "person" and (
                bool(group_id_norm) or deleted_only
            )
            if wide_person_fetch:
                fetch_size = 8_000
                fetch_page = 1
            else:
                fetch_size = size_n
                fetch_page = page_n
            evidence = list_evidence_items(
                db,
                job_id,
                artifact_name=evidence_name,
                page=fetch_page,
                page_size=fetch_size,
                hard_cap=fetch_size,
                sessions_only=want_sessions,
                person_id=group_id_norm if group_mode_preview == "person" else None,
            )
            if evidence is not None:
                rows = filter_evidence_rows_for_family(
                    family_norm, list(evidence.get("items") or [])
                )
                rows = strip_runtime_junk(rows, family=family_norm)

                # Contact list: skip sibling merge (was extracting thousands of
                # deleted messages just to build Name [deleted] rows). Thread
                # drill-down still merges that person's deleted residuals.
                if group_mode_preview == "person" and group_id_norm:
                    siblings = person_browse_evidence_names_for_family(family_norm)
                    if siblings:
                        seen_ids = {str(r.get("id")) for r in rows if r.get("id")}
                        for other_name in siblings:
                            if other_name == evidence_name:
                                continue
                            other = list_evidence_items(
                                db,
                                job_id,
                                artifact_name=other_name,
                                page=1,
                                page_size=fetch_size,
                                hard_cap=fetch_size,
                                sessions_only=False,
                                person_id=group_id_norm,
                            )
                            if not other:
                                continue
                            for item in other.get("items") or []:
                                iid = str(item.get("id") or "")
                                if iid and iid in seen_ids:
                                    continue
                                if iid:
                                    seen_ids.add(iid)
                                rows.append(item)
                        rows = strip_runtime_junk(rows, family=family_norm)
                        # Deleted board families stay deleted-focused even after merge.
                        if deleted_only:
                            rows = filter_evidence_rows_for_family(family_norm, rows)

                if q:
                    ql = q.lower()
                    rows = [
                        it
                        for it in rows
                        if ql in str(it.get("title") or "").lower()
                        or ql in str(it.get("source_path") or "").lower()
                        or ql in str((it.get("metadata") or {}).get("preview_body") or "").lower()
                        or ql in str((it.get("metadata") or {}).get("url") or "").lower()
                        or ql in str((it.get("metadata") or {}).get("conversation") or "").lower()
                        or ql in str((it.get("metadata") or {}).get("person_name") or "").lower()
                        or ql in str((it.get("metadata") or {}).get("body") or "").lower()
                        or ql in str((it.get("metadata") or {}).get("sender") or "").lower()
                    ]
                # Deleted-only board families default the thread tab to deleted.
                effective_filter = message_filter_norm
                if (
                    not effective_filter
                    and group_id_norm
                    and family_prefers_deleted_only(family_norm)
                ):
                    effective_filter = "deleted"

                rows, group_mode, thread_summary = apply_family_grouping(
                    rows,
                    job_id=job_id,
                    family=family_norm,
                    group_by=group_by,
                    group_id=group_id_norm,
                    message_filter=effective_filter,
                )
                # Thread responses must never contain people/group summary rows.
                if group_id_norm:
                    rows = [
                        r
                        for r in rows
                        if str(
                            ((r.get("metadata") or {}).get("evidence_kind") if isinstance(r.get("metadata"), dict) else None)
                            or r.get("artifact_type")
                            or ""
                        ).lower()
                        not in {"person", "group", "conversation", "album"}
                    ]
                # Cache deleted-board people so the next Open is instant.
                if (
                    deleted_only
                    and group_mode == "person"
                    and not group_id_norm
                    and rows
                    and not (q or "").strip()
                ):
                    from app.services.artifact_evidence_browse import _persist_browse_cache

                    _persist_browse_cache(db, job_id, "wa_deleted_persons_v14", rows)
                    try:
                        db.commit()
                    except Exception:
                        try:
                            db.rollback()
                        except Exception:
                            pass
                # Messaging family with zero recoverable chat rows → clear notice, never APK junk.
                if not rows:
                    rows = [no_chat_data_notice(family_norm, job_id, db=db)]
                    group_mode = None
                    thread_summary = None
                # Person thread / deleted board: wide window then page the result.
                # Live sessions list: already paged at the extractor.
                if wide_person_fetch:
                    total = len(rows)
                    start = (page_n - 1) * size_n
                    rows = rows[start : start + size_n]
                else:
                    source_total = int(evidence.get("total") or 0)
                    total = source_total if source_total > len(rows) else max(source_total, len(rows))
                domain = evidence.get("evidence_domain") or "family_evidence"
                if group_mode == "person" and not group_id_norm:
                    domain = "person"
                elif group_mode == "person" and group_id_norm:
                    domain = "person_thread"
                elif group_mode == "conversation" and not group_id_norm:
                    domain = "conversation"
                elif group_mode == "conversation" and group_id_norm:
                    domain = "conversation_thread"
                return {
                    **evidence,
                    "items": rows,
                    "total": total,
                    "page": page_n,
                    "page_size": size_n,
                    "evidence_domain": domain,
                    "evidence_label": family_norm,
                    "group_by": group_mode,
                    "group_id": group_id_norm,
                    "message_filter": effective_filter or "all",
                    "thread_summary": thread_summary,
                }

    # Catalog-key virtual evidence (when not in family mode).
    if (
        catalog_key
        and not family_norm
        and scope_norm not in {"all", "unclassified", "extensionless", "tiny"}
    ):
        from app.services.artifact_evidence_browse import (
            evidence_browse_mode,
            list_evidence_items,
            resolve_catalog_artifact,
        )
        from app.services.artifact_group_browse import (
            apply_family_grouping,
            person_browse_evidence_names_for_family,
        )
        from app.services.artifact_family_browse import (
            family_prefers_deleted_only,
            filter_evidence_rows_for_family,
            strip_runtime_junk,
        )

        ax = resolve_catalog_artifact(db, catalog_key)
        mode_hint = (
            evidence_browse_mode(
                str(ax.get("artifact_name") or ""),
                str(ax.get("category") or "") if ax else None,
            )
            if ax
            else None
        )
        message_modes = {
            "whatsapp_message",
            "whatsapp_group",
            "whatsapp_deleted_message",
            "sms_message",
            "chat_message",
            "deleted_social_message",
        }
        wide = mode_hint in message_modes
        catalog_sessions = (
            wide
            and mode_hint in {"whatsapp_message", "whatsapp_group"}
            and not group_id_norm
            and (group_by or "person").strip().lower() not in {"flat", "none", "off"}
        )
        # Sessions / threads need a wide extract window (then page after group/filter).
        # A 20-row page often returned empty while ChatStorage was still materializing.
        page_n = max(int(page or 1), 1)
        size_n = max(min(int(page_size or 20), 200), 1)
        wide_catalog_fetch = wide and (
            catalog_sessions or bool(group_id_norm) or mode_hint in {
                "whatsapp_deleted_message",
                "deleted_social_message",
            }
        )
        if wide_catalog_fetch:
            fetch_size = 8_000
            fetch_page = 1
        else:
            fetch_size = size_n
            fetch_page = page_n
        domain_probe = list_evidence_items(
            db,
            job_id,
            catalog_key=catalog_key,
            page=fetch_page,
            page_size=fetch_size,
            hard_cap=fetch_size,
            sessions_only=catalog_sessions,
            person_id=group_id_norm if wide else None,
        )
        # Sessions extract can return empty if ChatStorage is still materializing —
        # fall back to message/deleted rows so People / Groups is not stuck at 0.
        if (
            domain_probe is not None
            and catalog_sessions
            and not (domain_probe.get("items") or [])
            and not group_id_norm
        ):
            domain_probe = list_evidence_items(
                db,
                job_id,
                catalog_key=catalog_key,
                page=1,
                page_size=fetch_size,
                hard_cap=fetch_size,
                sessions_only=False,
                person_id=None,
            ) or domain_probe
        if domain_probe is not None:
            rows = list(domain_probe.get("items") or [])
            domain = str(domain_probe.get("evidence_domain") or "")
            # Map catalog message domains onto board families for person/group collapse.
            _DOMAIN_FAMILY = {
                "whatsapp_message": "whatsapp_messages",
                "whatsapp_group": "whatsapp_chats",
                "whatsapp_deleted_message": "whatsapp_deleted_messages",
                "sms_message": "sms",
                "chat_message": "telegram",
                "deleted_social_message": "deleted_social",
            }
            fam_for_group = _DOMAIN_FAMILY.get(domain)
            group_mode = None
            thread_summary = None
            if fam_for_group and (group_by or "").strip().lower() not in {"flat", "none", "off"}:
                # Same sibling merge as board Open — WhatsApp live + deleted so
                # contacts get Name and Name [deleted] rows.
                evidence_label = str(domain_probe.get("evidence_label") or "")
                siblings = person_browse_evidence_names_for_family(fam_for_group)
                if siblings and group_id_norm:
                    seen_ids = {str(r.get("id")) for r in rows if r.get("id")}
                    for other_name in siblings:
                        if evidence_label and other_name.lower() == evidence_label.lower():
                            continue
                        other = list_evidence_items(
                            db,
                            job_id,
                            artifact_name=other_name,
                            page=1,
                            page_size=fetch_size,
                            hard_cap=fetch_size,
                            sessions_only=False,
                            person_id=group_id_norm,
                        )
                        if not other:
                            continue
                        for item in other.get("items") or []:
                            iid = str(item.get("id") or "")
                            if iid and iid in seen_ids:
                                continue
                            if iid:
                                seen_ids.add(iid)
                            rows.append(item)
                    rows = strip_runtime_junk(rows, family=fam_for_group)
                    if family_prefers_deleted_only(fam_for_group):
                        rows = filter_evidence_rows_for_family(fam_for_group, rows)

                effective_filter = message_filter_norm
                if (
                    not effective_filter
                    and group_id_norm
                    and domain in {"whatsapp_deleted_message", "deleted_social_message"}
                ):
                    effective_filter = "deleted"
                rows, group_mode, thread_summary = apply_family_grouping(
                    rows,
                    job_id=job_id,
                    family=fam_for_group,
                    group_by=group_by or "person",
                    group_id=group_id_norm,
                    message_filter=effective_filter,
                )
                if group_mode == "person" and not group_id_norm:
                    domain = "person"
                elif group_mode == "person" and group_id_norm:
                    domain = "person_thread"
                elif group_mode == "conversation" and not group_id_norm:
                    domain = "conversation"
                elif group_mode == "conversation" and group_id_norm:
                    domain = "conversation_thread"
            if q:
                ql = q.lower()
                rows = [
                    it
                    for it in rows
                    if ql in str(it.get("title") or "").lower()
                    or ql in str(it.get("source_path") or "").lower()
                    or ql in str((it.get("metadata") or {}).get("url") or "").lower()
                    or ql in str((it.get("metadata") or {}).get("conversation") or "").lower()
                    or ql in str((it.get("metadata") or {}).get("person_name") or "").lower()
                    or ql in str((it.get("metadata") or {}).get("body") or "").lower()
                    or ql in str((it.get("metadata") or {}).get("sender") or "").lower()
                ]
            if wide_catalog_fetch:
                total = len(rows)
                start = (page_n - 1) * size_n
                rows = rows[start : start + size_n]
            else:
                source_total = int(domain_probe.get("total") or 0)
                total = source_total if source_total > len(rows) else max(source_total, len(rows))
            return {
                **domain_probe,
                "items": rows,
                "total": total,
                "page": page_n,
                "page_size": size_n,
                "evidence_domain": domain,
                "group_by": group_mode,
                "group_id": group_id_norm,
                "message_filter": message_filter_norm or "all",
                "thread_summary": thread_summary,
            }

    # Media / deleted / critical file families: album grouping + forensic file tabs.
    if family_norm and scope_norm not in {"all", "unclassified", "extensionless", "tiny"}:
        from app.services.artifact_file_forensics import (
            build_file_summary,
            family_supports_file_forensics,
            filter_file_rows,
        )
        from app.services.artifact_group_browse import (
            apply_family_grouping,
            family_supports_album_groups,
            resolve_group_mode,
        )

        album_mode = resolve_group_mode(family_norm, group_by)
        use_file_forensics = family_supports_file_forensics(family_norm)
        if (family_supports_album_groups(family_norm) and album_mode == "album") or use_file_forensics:
            from app.services.artifact_family_browse import family_where_sql, strip_runtime_junk
            from app.services.encyclopedia_match import encyclopedia_label_map, ensure_extended_encyclopedia

            fam_sql, fam_params = family_where_sql(family_norm)
            where = f"WHERE job_id=:jid{fam_sql}"
            page_n = max(int(page or 1), 1)
            size_n = max(min(int(page_size or 20), 200), 1)
            params: dict = {
                "jid": job_id,
                "limit": size_n,
                "offset": (page_n - 1) * size_n,
                **fam_params,
            }
            if q:
                where += " AND (file_path ILIKE :q OR file_name ILIKE :q OR coalesce(metadata->>'original_name','') ILIKE :q)"
                params["q"] = f"%{q}%"
            count_params = {k: v for k, v in params.items() if k not in {"limit", "offset"}}
            total_row = fetchone(db, f"SELECT count(*) c FROM job_artifacts {where}", count_params)
            file_total = int(total_row["c"]) if total_row else 0
            rows = fetchall(
                db,
                f"SELECT * FROM job_artifacts {where} ORDER BY file_path LIMIT :limit OFFSET :offset",
                params,
            )
            ensure_extended_encyclopedia(db)
            labels = encyclopedia_label_map(db)
            items = [_artifact_row(dict(r), labels) for r in rows]
            items = strip_runtime_junk(items, family=family_norm)

            file_summary = None
            effective_file_filter: str | None = file_filter_norm
            group_mode = None
            if use_file_forensics:
                # Default tab for dedicated deleted_* boards.
                if not effective_file_filter:
                    if family_norm == "deleted_photos":
                        effective_file_filter = "photos"
                    elif family_norm == "deleted_videos":
                        effective_file_filter = "videos"
                    elif family_norm == "deleted_documents":
                        effective_file_filter = "documents"
                    elif family_norm == "deleted_with_dates":
                        effective_file_filter = "with_dates"
                    elif family_norm == "anomalous_files":
                        effective_file_filter = "anomalous"
                    elif family_norm == "modified_files":
                        effective_file_filter = "modified"
                    elif family_norm in {"deleted_files", "critical_files"}:
                        effective_file_filter = "all"
                file_summary = build_file_summary(items)
                items = filter_file_rows(items, effective_file_filter or "all")

            group_mode = None
            if use_file_forensics:
                items.sort(
                    key=lambda r: (
                        str((r.get("metadata") or {}).get("deleted_at") or r.get("artifact_datetime") or ""),
                        str(r.get("source_path") or r.get("title") or ""),
                    ),
                    reverse=True,
                )

            domain = "file_forensics" if use_file_forensics else "file"
            return {
                "items": items,
                "total": file_total,
                "page": page_n,
                "page_size": size_n,
                "evidence_domain": domain,
                "evidence_label": family_norm,
                "group_by": group_mode,
                "group_id": group_id_norm,
                "file_filter": (effective_file_filter if use_file_forensics else None) or (
                    file_filter_norm if use_file_forensics else None
                ),
                "file_summary": file_summary,
            }

    offset = (max(page, 1) - 1) * page_size
    params: dict = {"jid": job_id, "limit": page_size, "offset": offset}
    where = "WHERE job_id=:jid"
    if family_norm:
        from app.services.artifact_family_browse import family_where_sql

        fam_sql, fam_params = family_where_sql(family_norm)
        where += fam_sql
        params.update(fam_params)
        # Family listing is an explicit evidence browse — ignore catalog filters.
        catalog_key = None
        catalog_section = None
    elif scope_norm in {"all", "unclassified", "extensionless", "tiny"}:
        # Explicit evidence browse — ignore catalog filters.
        catalog_key = None
        catalog_section = None
        if scope_norm == "unclassified":
            where += """ AND (
                encyclopedia_artifact_id IS NULL
                OR encyclopedia_artifact_id IN ('', 'unknown', 'unmatched', 'other')
            )"""
        elif scope_norm == "extensionless":
            where += """ AND (
                coalesce(nullif(trim(extension), ''), '') = ''
                OR lower(coalesce(extension,'')) IN ('.', '(none)', 'none')
            )"""
        elif scope_norm == "tiny":
            where += " AND coalesce(size_bytes, 0) <= 1024"
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
    total_row = fetchone(db, f"SELECT count(*) c FROM job_artifacts {where}", params)
    file_total = int(total_row["c"]) if total_row else 0
    file_offset = offset
    # When carved hits prepend the listing, shift allocated SQL offset.
    if catalog_key and scope_norm not in {"all", "unclassified", "extensionless", "tiny"}:
        from app.services.artifact_evidence_browse import merge_carve_into_file_listing

        probe = merge_carve_into_file_listing(
            db,
            job_id,
            catalog_key=catalog_key,
            file_items=[],
            file_total=file_total,
            page=page,
            page_size=page_size,
        )
        if probe is not None and "carve_prefix" in probe:
            carve_n = int(probe.get("carve_prefix") or 0)
            start = (max(page, 1) - 1) * page_size
            if start >= carve_n:
                file_offset = start - carve_n
            else:
                file_offset = 0
            params = {**params, "offset": file_offset}

    rows = fetchall(
        db,
        f"SELECT * FROM job_artifacts {where} ORDER BY file_path LIMIT :limit OFFSET :offset",
        params,
    )
    from app.services.encyclopedia_match import encyclopedia_label_map, ensure_extended_encyclopedia

    ensure_extended_encyclopedia(db)
    labels = encyclopedia_label_map(db)
    items = [_artifact_row(dict(r), labels) for r in rows]
    # Belt-and-suspenders: messaging Open must never list APK/DEX/ART.
    if family_norm:
        from app.services.artifact_family_browse import (
            no_chat_data_notice,
            strip_runtime_junk,
        )

        items = strip_runtime_junk(items, family=family_norm)
        messaging_empty = family_norm in {
            "facebook",
            "facebook_deleted",
            "instagram",
            "instagram_deleted",
            "telegram",
            "telegram_deleted",
            "signal",
            "signal_deleted",
            "linkedin",
            "whatsapp_messages",
            "whatsapp_chats",
            "whatsapp_deleted_messages",
        }
        if not items and messaging_empty:
            items = [no_chat_data_notice(family_norm, job_id, db=db)]
            file_total = 1
    if catalog_key and scope_norm not in {"all", "unclassified", "extensionless", "tiny"}:
        from app.services.artifact_evidence_browse import merge_carve_into_file_listing

        merged = merge_carve_into_file_listing(
            db,
            job_id,
            catalog_key=catalog_key,
            file_items=items,
            file_total=file_total,
            page=page,
            page_size=page_size,
        )
        if merged is not None:
            merged.pop("_needs_file_offset", None)
            return merged
    return {
        "items": items,
        "total": file_total,
        "page": page,
        "page_size": page_size,
        "evidence_domain": "file",
    }


@router.get("/{job_id}/artifacts/categories")
def artifact_categories(
    job_id: str,
    db: Session = Depends(firm_db),
    current: CurrentUser = Depends(require_firm_permission("artifact:read")),
):
    from app.services.encyclopedia_match import encyclopedia_label_map, ensure_extended_encyclopedia

    ensure_extended_encyclopedia(db)
    labels = encyclopedia_label_map(db)
    rows = fetchall(
        db,
        """SELECT encyclopedia_artifact_id as cat, count(*) c FROM job_artifacts
           WHERE job_id=:jid GROUP BY encyclopedia_artifact_id ORDER BY c DESC""",
        {"jid": job_id},
    )
    categories = []
    for r in rows:
        key = r["cat"] or "unmatched"
        categories.append({
            "key": key,
            "label": labels.get(key, "Unmatched" if key == "unmatched" else key),
            "count": int(r["c"]),
        })
    return {"categories": categories}


@router.get("/{job_id}/artifacts/resolve-path")
def resolve_artifact_by_path(
    job_id: str,
    path: str = Query(..., min_length=1, description="Evidence file_path (exact or suffix match)"),
    db: Session = Depends(firm_db),
    current: CurrentUser = Depends(require_firm_permission("artifact:read")),
):
    """Resolve a board/sample path to an openable job_artifacts row."""
    norm = path.replace("\\", "/").strip()
    if not norm:
        raise HTTPException(status_code=400, detail={"error": {"code": "bad_path", "message": "path required"}})
    row = fetchone(
        db,
        """SELECT * FROM job_artifacts
           WHERE job_id=:jid
             AND (
               replace(file_path, '\\\\', '/') = :p
               OR lower(replace(file_path, '\\\\', '/')) = lower(:p)
               OR lower(replace(file_path, '\\\\', '/')) LIKE lower(:suf)
               OR lower(replace(file_path, '\\\\', '/')) LIKE lower(:mid)
             )
           ORDER BY
             CASE WHEN replace(file_path, '\\\\', '/') = :p THEN 0 ELSE 1 END,
             length(file_path)
           LIMIT 1""",
        {"jid": job_id, "p": norm, "suf": f"%/{norm.split('/')[-1]}", "mid": f"%{norm[-120:]}"},
    )
    if not row:
        raise HTTPException(
            status_code=404,
            detail={"error": {"code": "not_found", "message": "No artifact matches that path"}},
        )
    return _artifact_row(dict(row))


@router.get("/{job_id}/artifact-review")
def artifact_review_summary(
    job_id: str,
    limit: int = Query(120, ge=1, le=500),
    db: Session = Depends(firm_db),
    current: CurrentUser = Depends(require_firm_permission("artifact:read")),
):
    """Examiner-review signal summary across the job's actual evidence files."""
    from app.services.artifact_review import job_review_summary

    job = fetchone(db, "SELECT id FROM jobs WHERE id=:id", {"id": job_id})
    if not job:
        raise HTTPException(status_code=404, detail={"error": {"code": "not_found", "message": "Job not found"}})
    return job_review_summary(db, job_id, limit=limit)


@router.get("/{job_id}/artifacts/{artifact_id}/properties")
def artifact_properties(
    job_id: str,
    artifact_id: str,
    db: Session = Depends(firm_db),
    current: CurrentUser = Depends(require_firm_permission("artifact:read")),
):
    """Return actual evidence-file size/media dimensions/duration for the examiner."""
    from app.services.artifact_media_properties import get_artifact_media_properties

    try:
        return get_artifact_media_properties(db, job_id, artifact_id)
    except LookupError:
        raise HTTPException(status_code=404, detail={"error": {"code": "not_found", "message": "Artifact not found"}})


@router.get("/{job_id}/artifacts/{artifact_id}/review")
def artifact_review_detail(
    job_id: str,
    artifact_id: str,
    db: Session = Depends(firm_db),
    current: CurrentUser = Depends(require_firm_permission("artifact:read")),
):
    """Deep review flags using parsed text, OCR and image-description evidence."""
    from app.services.artifact_review import artifact_review

    try:
        return artifact_review(db, job_id, artifact_id)
    except LookupError:
        raise HTTPException(status_code=404, detail={"error": {"code": "not_found", "message": "Artifact not found"}})


@router.get("/{job_id}/artifacts/{artifact_id}")
def get_artifact(
    job_id: str,
    artifact_id: str,
    db: Session = Depends(firm_db),
    current: CurrentUser = Depends(require_firm_permission("artifact:read")),
):
    from app.services.artifact_preview import _load_artifact_row
    from app.services.encyclopedia_match import encyclopedia_label_map, ensure_extended_encyclopedia

    # Virtual evidence ids (ev-wa-…) are not job_artifacts UUIDs — never hit Postgres uuid cast.
    row = _load_artifact_row(db, job_id, artifact_id)
    if not row:
        raise HTTPException(
            status_code=404,
            detail={
                "error": {
                    "code": "not_found",
                    "message": (
                        "Artifact not found. Parsed message rows use virtual ids — "
                        "open the source database file instead."
                    ),
                }
            },
        )
    ensure_extended_encyclopedia(db)
    return _artifact_row(row, encyclopedia_label_map(db))


@router.get("/{job_id}/artifacts/{artifact_id}/preview")
def preview_artifact(
    job_id: str,
    artifact_id: str,
    db: Session = Depends(firm_db),
    current: CurrentUser = Depends(require_firm_permission("artifact:read")),
):
    from app.services.artifact_preview import build_artifact_preview

    try:
        return build_artifact_preview(db, job_id, artifact_id)
    except LookupError:
        raise HTTPException(
            status_code=404,
            detail={
                "error": {
                    "code": "not_found",
                    "message": (
                        "Artifact not found. Parsed message rows use virtual ids — "
                        "open the source database file instead."
                    ),
                }
            },
        )


@router.get("/{job_id}/artifacts/{artifact_id}/content")
def artifact_content(
    job_id: str,
    artifact_id: str,
    download: bool = Query(False, description="Force attachment download (large forensic files)"),
    db: Session = Depends(firm_db),
    current: CurrentUser = Depends(require_firm_permission("artifact:read")),
):
    from app.services.artifact_preview import (
        ArtifactContentTooLargeError,
        _artifact_filename_and_type,
        _load_artifact_row,
        _size_hint_bytes,
        iter_artifact_content,
        load_artifact_content,
        _CONTENT_READ_MAX_BYTES,
    )

    row = _load_artifact_row(db, job_id, artifact_id)
    if not row:
        raise HTTPException(status_code=404, detail={"error": {"code": "not_found", "message": "Artifact not found"}})
    disposition = "attachment" if download else "inline"
    hint = _size_hint_bytes(row) or 0
    # Stream large evidence so examiners can open UFED media / DBs without 413.
    stream_threshold = 8 * 1024 * 1024
    if download or hint >= stream_threshold:
        # Sniff a tiny head so extensionless files get a real download name/type.
        head = b""
        try:
            for chunk in iter_artifact_content(db, job_id, row, max_bytes=64):
                head += chunk
                if len(head) >= 64:
                    break
        except Exception:
            head = b""
        filename, content_type = _artifact_filename_and_type(row, head=head)
        try:
            gen = iter_artifact_content(db, job_id, row, max_bytes=_CONTENT_READ_MAX_BYTES)
        except FileNotFoundError as exc:
            raise HTTPException(status_code=404, detail={"error": {"code": "not_found", "message": str(exc)}})
        headers = {
            "Content-Disposition": f'{disposition}; filename="{filename}"',
            "Cache-Control": "private, max-age=60",
            "X-Content-Type-Options": "nosniff",
        }
        if hint > 0:
            headers["Content-Length"] = str(min(hint, _CONTENT_READ_MAX_BYTES))
        return StreamingResponse(gen, media_type=content_type, headers=headers)

    try:
        data, content_type, filename = load_artifact_content(db, job_id, artifact_id)
    except LookupError:
        raise HTTPException(status_code=404, detail={"error": {"code": "not_found", "message": "Artifact not found"}})
    except FileNotFoundError as exc:
        raise HTTPException(status_code=404, detail={"error": {"code": "not_found", "message": str(exc)}})
    except ArtifactContentTooLargeError as exc:
        # Fall back to streaming instead of failing forensic open.
        filename, content_type = _artifact_filename_and_type(row)
        try:
            gen = iter_artifact_content(db, job_id, row, max_bytes=_CONTENT_READ_MAX_BYTES)
            headers = {
                "Content-Disposition": f'attachment; filename="{filename}"',
                "Cache-Control": "private, max-age=60",
            }
            if exc.size_bytes:
                headers["Content-Length"] = str(min(exc.size_bytes, _CONTENT_READ_MAX_BYTES))
            return StreamingResponse(gen, media_type=content_type, headers=headers)
        except Exception:
            raise HTTPException(
                status_code=413,
                detail={
                    "error": {
                        "code": "content_too_large",
                        "message": (
                            f"File is {exc.size_bytes:,} bytes — download limit is "
                            f"{exc.limit_bytes // (1024 * 1024)} MB. Use Export or host browse."
                        ),
                    }
                },
            )
    headers = {"Content-Disposition": f'{disposition}; filename="{filename}"'}
    return Response(content=data, media_type=content_type, headers=headers)


@router.get("/{job_id}/artifacts/{artifact_id}/email-attachments/{part_index}/content")
def email_attachment_content(
    job_id: str,
    artifact_id: str,
    part_index: int,
    db: Session = Depends(firm_db),
    current: CurrentUser = Depends(require_firm_permission("artifact:read")),
):
    from app.services.artifact_preview import load_email_attachment_content

    try:
        data, content_type, filename = load_email_attachment_content(db, job_id, artifact_id, part_index)
    except LookupError:
        raise HTTPException(status_code=404, detail={"error": {"code": "not_found", "message": "Attachment not found"}})
    except FileNotFoundError as exc:
        raise HTTPException(status_code=404, detail={"error": {"code": "not_found", "message": str(exc)}})
    headers = {"Content-Disposition": f'inline; filename="{filename}"'}
    return Response(content=data, media_type=content_type, headers=headers)


@router.get("/{job_id}/file-tree")
def file_tree(
    job_id: str,
    db: Session = Depends(firm_db),
    current: CurrentUser = Depends(require_firm_permission("artifact:read")),
):
    rows = fetchall(
        db,
        "SELECT file_path, size_bytes FROM job_artifacts WHERE job_id=:jid ORDER BY file_path LIMIT 5000",
        {"jid": job_id},
    )
    return {"job_id": job_id, "entries": [{"path": r["file_path"], "size_bytes": r.get("size_bytes")} for r in rows]}
