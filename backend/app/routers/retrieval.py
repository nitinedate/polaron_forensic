"""Hybrid retrieval, query understanding, and grounded answers API."""

from __future__ import annotations

import re
import time

from fastapi import APIRouter, Depends
from pydantic import BaseModel
from sqlalchemy.orm import Session

from app.deps import CurrentUser, firm_db, require_firm_permission
from app.retrieval.answer import compose_answer
from app.retrieval.hybrid import hybrid_retrieve
from app.retrieval.query_decompose import decompose_query
from app.retrieval.query_understand import understand_query
from app.services.disk_build_log import write_disk_log_committed

router = APIRouter(prefix="/api/jobs", tags=["retrieval"])


def _serialize_retrieve_items(composed: dict, *, fallback_chunks: list | None = None) -> list[dict]:
    items = []
    for c in composed.get("items") or fallback_chunks or []:
        items.append(
            {
                "id": str(c.get("id") or ""),
                "job_id": str(c.get("job_id")) if c.get("job_id") else None,
                "file_path": c.get("file_path"),
                "content": c.get("content"),
                "artifact_id": c.get("artifact_id"),
                "chunk_type": c.get("chunk_type"),
                "metadata": c.get("metadata") if isinstance(c.get("metadata"), dict) else {},
                "score": c.get("score"),
                "rrf_score": c.get("rrf_score"),
                "rerank_score": c.get("rerank_score"),
            }
        )
    return items


def _finish_retrieve_response(
    *,
    schema: str,
    job_id: str,
    q: str,
    composed: dict,
    t0: float,
    fallback_chunks: list | None = None,
) -> dict:
    elapsed = round(time.monotonic() - t0, 1)
    items = _serialize_retrieve_items(composed, fallback_chunks=fallback_chunks)
    answer_preview = (composed.get("answer") or "")[:280].replace("\n", " ")
    write_disk_log_committed(
        schema,
        job_id,
        f"Q&A answered in {elapsed}s — confidence={composed.get('confidence') or 'n/a'} — {answer_preview}",
        stage="rag_qa",
        level="info" if composed.get("answer") else "warning",
        metadata={
            "query": q[:500],
            "elapsed_sec": elapsed,
            "confidence": composed.get("confidence"),
            "chunk_count": len(items),
            "grounded": composed.get("grounded"),
        },
    )
    return {
        "answer": composed.get("answer"),
        "confidence": composed.get("confidence"),
        "grounded": composed.get("grounded", True),
        "facts": composed.get("facts") or {},
        "citations": composed.get("citations") or [],
        "items": items,
        "total": composed.get("total", len(items)),
    }


def _retrieve_collectors(q: str) -> dict[str, bool]:
    """Decide which expensive evidence collectors a query actually needs."""
    from app.retrieval.answer import (
        _BROWSER_INTENT,
        _COUNT_INTENT,
        _EMAIL_INTENT,
        _HARDWARE_INTENT,
        _OS_ARTIFACTS_INTENT,
        _OS_INTENT,
        _PHONE_INTENT,
        _PHONE_USAGE_INTENT,
        _SECTION_INTENT,
        _USB_INTENT,
        _USB_USAGE_INTENT,
        _USER_INTENT,
        _WHATSAPP_INTENT,
    )

    q = q or ""
    user = bool(_USER_INTENT.search(q))
    os_identity = bool(_OS_INTENT.search(q) and not _OS_ARTIFACTS_INTENT.search(q))
    hardware = bool(_HARDWARE_INTENT.search(q) and not _OS_INTENT.search(q))
    count = bool(_COUNT_INTENT.search(q) and not _OS_ARTIFACTS_INTENT.search(q))
    sections = bool(
        _SECTION_INTENT.search(q)
        or re.search(r"\b(axiom|artifact\s+sections?|b\.\s*artifacts)\b", q, re.I)
    )
    usb = bool(_USB_INTENT.search(q) or _USB_USAGE_INTENT.search(q))
    phone = bool(_PHONE_INTENT.search(q) or _PHONE_USAGE_INTENT.search(q))
    browser = bool(_BROWSER_INTENT.search(q))
    email = bool(_EMAIL_INTENT.search(q))
    whatsapp = bool(_WHATSAPP_INTENT.search(q))
    encyclopedia = False
    try:
        from app.services.forensic_inventory import detect_encyclopedia_category_query

        encyclopedia = bool(detect_encyclopedia_category_query(q))
    except Exception:
        pass
    document = False
    try:
        from app.services.forensic_inventory import detect_document_query

        document = bool(detect_document_query(q))
    except Exception:
        pass
    broad = bool(sections or count or usb or phone or browser or email or whatsapp or encyclopedia or document)
    return {
        "user": user,
        "os_identity": os_identity,
        "inventory": count or broad,
        "sections": sections or broad,
        "usb": usb,
        "phone": phone,
        "browser": browser,
        "email": email,
        "whatsapp": whatsapp,
        "encyclopedia": encyclopedia,
        "document": document,
        "profile": user or os_identity or hardware,
    }


class RetrieveBody(BaseModel):
    query: str
    filters: dict | None = None
    top_k: int = 10
    include_answer: bool = True


class QueryUnderstandBody(BaseModel):
    query: str


_CONFIDENCE_RANK = {"high": 3, "medium": 2, "low": 1, "none": 0}


def _merge_compound_responses(
    *,
    schema: str,
    job_id: str,
    original_query: str,
    sub_questions: list[str],
    parts: list[dict],
    t0: float,
) -> dict:
    sections: list[str] = []
    all_items: list[dict] = []
    seen_ids: set[str] = set()
    merged_facts: dict = {"sub_questions": sub_questions, "parts": []}
    worst_conf = "high"

    for sub_q, part in zip(sub_questions, parts):
        ans = (part.get("answer") or "").strip()
        if ans:
            sections.append(f"**{sub_q}**\n\n{ans}")
        merged_facts["parts"].append(
            {
                "query": sub_q,
                "confidence": part.get("confidence"),
                "grounded": part.get("grounded"),
            }
        )
        conf = str(part.get("confidence") or "none").lower()
        if _CONFIDENCE_RANK.get(conf, 0) < _CONFIDENCE_RANK.get(worst_conf, 3):
            worst_conf = conf
        for item in part.get("items") or []:
            iid = str(item.get("id") or "")
            key = iid or f"{item.get('file_path')}-{str(item.get('content', ''))[:80]}"
            if key in seen_ids:
                continue
            seen_ids.add(key)
            all_items.append(item)
        for key, value in (part.get("facts") or {}).items():
            if key in ("sub_questions", "parts"):
                continue
            merged_facts[key] = value

    answer = "\n\n".join(sections) if sections else None
    composed = {
        "answer": answer,
        "confidence": worst_conf if answer else "none",
        "grounded": all(part.get("grounded", True) for part in parts),
        "facts": merged_facts,
        "citations": [],
        "items": all_items,
        "total": len(all_items),
    }
    return _finish_retrieve_response(
        schema=schema,
        job_id=job_id,
        q=original_query,
        composed=composed,
        t0=t0,
    )


def _execute_retrieve(
    *,
    db: Session,
    job_id: str,
    sub_q: str,
    body: RetrieveBody,
    current: CurrentUser,
    schema: str,
) -> dict:
    q = sub_q.strip()
    needs = _retrieve_collectors(q)
    try:
        from app.retrieval.answer import (
            _BROWSER_INTENT,
            _COUNT_INTENT,
            _EMAIL_INTENT,
            _PHONE_INTENT,
            _PHONE_USAGE_INTENT,
            _SECTION_INTENT,
            _USB_INTENT,
            _USB_USAGE_INTENT,
            _WHATSAPP_INTENT,
        )
        from app.services.forensic_inventory import prioritize_pending_forensic_parse
        from app.services.artifact_sections import is_section_summary_query

        if not is_section_summary_query(q) and (
            _USB_INTENT.search(q)
            or _USB_USAGE_INTENT.search(q)
            or _PHONE_INTENT.search(q)
            or _PHONE_USAGE_INTENT.search(q)
            or _BROWSER_INTENT.search(q)
            or _EMAIL_INTENT.search(q)
            or _WHATSAPP_INTENT.search(q)
            or _SECTION_INTENT.search(q)
        ):
            prioritize_pending_forensic_parse(db, job_id, limit=40)
            db.commit()
        if _COUNT_INTENT.search(q):
            from app.db.sql_helpers import fetchone

            pending = fetchone(
                db,
                "SELECT count(*) c FROM job_artifacts WHERE job_id=:j AND parse_status='pending'",
                {"j": job_id},
            )
            if pending and int(pending["c"] or 0) > 500:
                try:
                    from app.tasks import parse_drain_task

                    parse_drain_task.delay(current.schema_name, job_id)
                except Exception:
                    pass
    except Exception:
        try:
            db.rollback()
        except Exception:
            pass

    chunks = hybrid_retrieve(
        db,
        job_id,
        q,
        filters=body.filters,
        top_k=body.top_k,
        schema_name=current.schema_name,
    )
    from app.db.session import apply_firm_search_path

    apply_firm_search_path(db, current.schema_name)
    if not body.include_answer:
        return {"items": chunks, "total": len(chunks), "answer": None, "citations": [], "confidence": None}

    account_timeline = None
    os_facts = None
    inventory = None
    usb_devices = None
    usb_usage = None
    phone_info = None
    document_info = None
    section_inventory = None
    encyclopedia_category = None
    browser_urls = None
    email_info = None
    whatsapp_info = None

    if needs["inventory"]:
        try:
            from app.services.forensic_inventory import collect_job_inventory

            inventory = collect_job_inventory(db, job_id)
        except Exception:
            try:
                db.rollback()
            except Exception:
                pass
            apply_firm_search_path(db, current.schema_name)
            inventory = None

    if needs["document"]:
        try:
            from app.services.forensic_inventory import collect_documents_by_type, detect_document_query

            detected = detect_document_query(q)
            if detected:
                label, exts = detected
                document_info = collect_documents_by_type(db, job_id, extensions=exts, label=label)
        except Exception:
            try:
                db.rollback()
            except Exception:
                pass
            apply_firm_search_path(db, current.schema_name)
            document_info = None

    if needs["encyclopedia"]:
        try:
            from app.services.forensic_inventory import (
                collect_encyclopedia_category_breakdown,
                detect_encyclopedia_category_query,
            )

            cat = detect_encyclopedia_category_query(q)
            if cat:
                encyclopedia_category = collect_encyclopedia_category_breakdown(db, job_id, cat)
        except Exception:
            try:
                db.rollback()
            except Exception:
                pass
            apply_firm_search_path(db, current.schema_name)
            encyclopedia_category = None

    if needs["sections"]:
        try:
            from app.db.session import apply_firm_search_path
            from app.services.artifact_sections import build_job_artifact_sections, ensure_section_rag_chunks

            apply_firm_search_path(db, current.schema_name)
            section_inventory = build_job_artifact_sections(
                db, job_id, schema_name=current.schema_name
            )
            try:
                ensure_section_rag_chunks(db, job_id, section_inventory)
                db.commit()
                apply_firm_search_path(db, current.schema_name)
            except Exception:
                try:
                    db.rollback()
                except Exception:
                    pass
                apply_firm_search_path(db, current.schema_name)
        except Exception:
            try:
                db.rollback()
            except Exception:
                pass
            from app.db.session import apply_firm_search_path

            apply_firm_search_path(db, current.schema_name)
            section_inventory = None

    if needs["profile"] or needs["usb"] or needs["phone"] or needs["browser"] or needs["email"] or needs["whatsapp"]:
        try:
            from app.services.forensic_profile_index import collect_account_timeline, collect_os_facts
            from app.services.forensic_inventory import (
                collect_browser_urls,
                collect_email_artifacts,
                collect_phone_usage,
                collect_usb_devices,
                collect_usb_usage_events,
                collect_whatsapp_artifacts,
                ensure_usb_fact_chunks,
            )

            if needs["profile"]:
                account_timeline = collect_account_timeline(db, job_id)
                os_facts = collect_os_facts(db, job_id)
            if needs["usb"]:
                usb_devices = collect_usb_devices(db, job_id)
                usb_usage = collect_usb_usage_events(db, job_id)
                if usb_devices:
                    ensure_usb_fact_chunks(db, job_id)
            if needs["phone"]:
                phone_info = collect_phone_usage(db, job_id)
            if needs["browser"]:
                browser_urls = collect_browser_urls(db, job_id)
            if needs["email"]:
                email_info = collect_email_artifacts(db, job_id)
            if needs["whatsapp"]:
                whatsapp_info = collect_whatsapp_artifacts(db, job_id)
            db.commit()
        except Exception:
            try:
                db.rollback()
            except Exception:
                pass

    composed = compose_answer(
        q,
        chunks,
        account_timeline=account_timeline,
        os_facts=os_facts,
        inventory=inventory,
        usb_devices=usb_devices,
        usb_usage=usb_usage,
        phone_info=phone_info,
        document_info=document_info,
        section_inventory=section_inventory,
        encyclopedia_category=encyclopedia_category,
        browser_urls=browser_urls,
        email_info=email_info,
        whatsapp_info=whatsapp_info,
        db=db,
        job_id=job_id,
        schema_name=current.schema_name,
    )
    return {
        "answer": composed.get("answer"),
        "confidence": composed.get("confidence"),
        "grounded": composed.get("grounded", True),
        "facts": composed.get("facts") or {},
        "citations": composed.get("citations") or [],
        "items": _serialize_retrieve_items(composed, fallback_chunks=chunks),
        "total": composed.get("total", len(chunks)),
    }


@router.post("/{job_id}/retrieve")
def retrieve(
    job_id: str,
    body: RetrieveBody,
    db: Session = Depends(firm_db),
    current: CurrentUser = Depends(require_firm_permission("artifact:read")),
):
    q = (body.query or "").strip()
    schema = current.schema_name
    t0 = time.monotonic()
    write_disk_log_committed(
        schema,
        job_id,
        f"Q&A query received: {q[:240]}",
        stage="rag_qa",
        metadata={"query": q[:500], "top_k": body.top_k},
    )

    # Fast path: Axiom section / data-leakage inventory — SQL collectors only (no BGE-M3 embed).
    try:
        from app.db.session import apply_firm_search_path
        from app.services.artifact_sections import build_job_artifact_sections, is_section_summary_query

        if is_section_summary_query(q):
            apply_firm_search_path(db, schema)
            section_inventory = build_job_artifact_sections(
                db, job_id, schema_name=schema,
            )
            composed = compose_answer(body.query, [], section_inventory=section_inventory)
            return _finish_retrieve_response(
                schema=schema,
                job_id=job_id,
                q=q,
                composed=composed,
                t0=t0,
            )
    except Exception as exc:
        try:
            db.rollback()
        except Exception:
            pass
        elapsed = round(time.monotonic() - t0, 1)
        write_disk_log_committed(
            schema,
            job_id,
            f"Q&A section summary failed after {elapsed}s: {exc}",
            stage="rag_qa",
            level="error",
        )
        raise

    # Fast path: OS / Users / hardware — structured hive facts, skip embedding + multi-tool agent.
    try:
        from app.db.session import apply_firm_search_path
        from app.retrieval.answer import (
            _HARDWARE_INTENT,
            _OS_ARTIFACTS_INTENT,
            _OS_INTENT,
            _USER_INTENT,
        )

        apply_firm_search_path(db, schema)
        if body.include_answer and _USER_INTENT.search(q):
            from app.services.identity_evidence_prompts import answer_users_with_prompt

            special = answer_users_with_prompt(
                db, job_id, q, schema_name=schema, output_format="qa",
            )
            if special and (special.get("answer") or "").strip():
                write_disk_log_committed(
                    schema, job_id, "Q&A users fast-path (no embed)", stage="rag_qa",
                )
                return _finish_retrieve_response(
                    schema=schema, job_id=job_id, q=q, composed=special, t0=t0,
                )
        if (
            body.include_answer
            and _OS_INTENT.search(q)
            and not _OS_ARTIFACTS_INTENT.search(q)
            and not _HARDWARE_INTENT.search(q)
        ):
            from app.services.identity_evidence_prompts import answer_os_with_prompt

            special = answer_os_with_prompt(
                db, job_id, q, schema_name=schema, output_format="qa",
            )
            if special and (special.get("answer") or "").strip():
                write_disk_log_committed(
                    schema, job_id, "Q&A OS fast-path (no embed)", stage="rag_qa",
                )
                return _finish_retrieve_response(
                    schema=schema, job_id=job_id, q=q, composed=special, t0=t0,
                )
        if body.include_answer and _HARDWARE_INTENT.search(q) and not _OS_INTENT.search(q):
            from app.services.identity_evidence_prompts import answer_hardware_with_prompt

            special = answer_hardware_with_prompt(
                db, job_id, q, schema_name=schema, output_format="qa",
            )
            if special and (special.get("answer") or "").strip():
                write_disk_log_committed(
                    schema, job_id, "Q&A hardware fast-path (no embed)", stage="rag_qa",
                )
                return _finish_retrieve_response(
                    schema=schema, job_id=job_id, q=q, composed=special, t0=t0,
                )
    except Exception as exc:
        try:
            db.rollback()
        except Exception:
            pass
        write_disk_log_committed(
            schema,
            job_id,
            f"Q&A identity fast-path failed (falling back): {exc}",
            stage="rag_qa",
            level="warning",
        )
    sub_questions = decompose_query(q)
    if len(sub_questions) > 1:
        write_disk_log_committed(
            schema,
            job_id,
            f"Q&A compound query — answering {len(sub_questions)} sub-questions sequentially",
            stage="rag_qa",
            metadata={"query": q[:500], "sub_questions": sub_questions},
        )
        parts: list[dict] = []
        for sub_q in sub_questions:
            parts.append(
                _execute_retrieve(
                    db=db,
                    job_id=job_id,
                    sub_q=sub_q,
                    body=body,
                    current=current,
                    schema=schema,
                )
            )
        return _merge_compound_responses(
            schema=schema,
            job_id=job_id,
            original_query=q,
            sub_questions=sub_questions,
            parts=parts,
            t0=t0,
        )

    part = _execute_retrieve(
        db=db,
        job_id=job_id,
        sub_q=q,
        body=body,
        current=current,
        schema=schema,
    )
    composed = {
        "answer": part.get("answer"),
        "confidence": part.get("confidence"),
        "grounded": part.get("grounded", True),
        "facts": part.get("facts") or {},
        "citations": part.get("citations") or [],
        "items": part.get("items") or [],
        "total": part.get("total", 0),
    }
    return _finish_retrieve_response(
        schema=schema,
        job_id=job_id,
        q=q,
        composed=composed,
        t0=t0,
    )


@router.post("/{job_id}/query/understand")
def query_understand(
    job_id: str,
    body: QueryUnderstandBody,
    current: CurrentUser = Depends(require_firm_permission("artifact:read")),
):
    result = understand_query(body.query)
    result["sub_questions"] = decompose_query(body.query)
    return result
