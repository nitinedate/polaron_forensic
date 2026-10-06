"""Hybrid retrieval — BM25 + vector + keyword + parse-result scan + graph expand + rerank."""

from __future__ import annotations

import json
import logging
import re

from app.config import get_settings
from app.db.sql_helpers import execute, fetchall
from app.retrieval.rerank import rerank_chunks
from app.services.embedding_gpu import embed_texts
from app.services.neo4j_sync import _get_driver, graph_expand
from app.services.opensearch_sync import search_bm25

log = logging.getLogger("hybrid_retrieval")

_USER_INTENT = re.compile(
    r"\b(users?|accounts?|profiles?|who\s+used|logged\s+in|login|logon|username|"
    r"password\s+chang|last\s+logon|last\s+login)\b",
    re.I,
)
_OS_INTENT = re.compile(
    r"\b(operating\s+system|os\s+details?|windows\s+version|which\s+os|what\s+os|"
    r"product\s*name|build\s+number|computer\s*name)\b",
    re.I,
)

_STOP = frozenset({
    "the", "and", "for", "who", "used", "this", "with", "from", "provide", "list",
    "what", "which", "when", "where", "how", "are", "was", "were", "does", "did",
    "along", "also", "please", "show", "give", "tell", "about",
})


def _section_summary_intent(query: str) -> bool:
    try:
        from app.services.artifact_sections import is_section_summary_query

        return is_section_summary_query(query)
    except Exception:
        return False


def _gpu_indexing_active(db, job_id: str) -> bool:
    """True when the RAG worker is likely holding the GPU for background embedding."""
    try:
        from app.db.sql_helpers import fetchone

        row = fetchone(db, "SELECT status FROM jobs WHERE id=:id", {"id": job_id})
        return (row or {}).get("status") == "indexing"
    except Exception:
        return False


def _query_embedding_device(db, job_id: str) -> str:
    settings = get_settings()
    device = settings.rag_embedding_device or "cpu"
    if not str(device).startswith("cuda"):
        return device
    try:
        from app.db.sql_helpers import fetchone

        row = fetchone(db, "SELECT status FROM jobs WHERE id=:id", {"id": job_id})
        status = (row or {}).get("status") or ""
        # Reserve GPU for background indexing; single-query embed on CPU avoids 30s+ model load contention.
        if status in ("indexing", "indexed", "ready", "completed", "report_ready"):
            return "cpu"
    except Exception:
        pass
    return device


def _vector_search(db, query: str, *, job_id: str, limit: int = 20) -> list[dict]:
    settings = get_settings()
    try:
        vectors = embed_texts(
            [query],
            model_name=settings.rag_embedding_model,
            device=_query_embedding_device(db, job_id),
            batch_size=1,
        )
    except Exception as exc:
        log.warning("Vector search skipped (embed failed): %s", exc)
        return []
    if not vectors or not vectors[0]:
        return []
    vec_str = "[" + ",".join(f"{v:.8f}" for v in vectors[0]) + "]"
    rows = fetchall(
        db,
        """SELECT id, job_id, file_path, content, artifact_id, chunk_type, metadata,
                  1 - (embedding_v2 <=> CAST(:emb AS vector)) AS score
           FROM rag_chunks
           WHERE (job_id = :jid OR job_id IS NULL) AND embedding_v2 IS NOT NULL
           ORDER BY embedding_v2 <=> CAST(:emb AS vector)
           LIMIT :lim""",
        {"emb": vec_str, "jid": job_id, "lim": limit},
    )
    return [dict(r) for r in rows]


def _tsvector_search(db, query: str, *, job_id: str, limit: int = 20) -> list[dict]:
    rows = fetchall(
        db,
        """SELECT id, job_id, file_path, content, artifact_id, chunk_type, metadata,
                  ts_rank(to_tsvector('english', coalesce(content,'')), plainto_tsquery('english', :q)) AS score
           FROM rag_chunks
           WHERE (job_id = :jid OR job_id IS NULL)
             AND to_tsvector('english', coalesce(content,'')) @@ plainto_tsquery('english', :q)
           ORDER BY score DESC
           LIMIT :lim""",
        {"q": query, "jid": job_id, "lim": limit},
    )
    return [dict(r) for r in rows]


def _keyword_search(db, query: str, *, job_id: str, limit: int = 40) -> list[dict]:
    """ILIKE across chunk content and paths — broad file coverage."""
    tokens = [t for t in re.findall(r"[A-Za-z0-9_]{3,}", query) if t.lower() not in _STOP]
    if not tokens:
        tokens = [query.strip()[:40]] if query.strip() else []
    if not tokens:
        return []

    clauses = []
    params: dict = {"jid": job_id, "lim": limit}
    for i, tok in enumerate(tokens[:8]):
        key = f"t{i}"
        params[key] = f"%{tok}%"
        clauses.append(f"(content ILIKE :{key} OR file_path ILIKE :{key})")
    where = " OR ".join(clauses)
    rows = fetchall(
        db,
        f"""SELECT id, job_id, file_path, content, artifact_id, chunk_type, metadata, 0.5 AS score
            FROM rag_chunks
            WHERE (job_id = :jid OR job_id IS NULL) AND ({where})
            ORDER BY CASE WHEN file_path = '__forensic__/artifact_sections' THEN 0
                          WHEN file_path LIKE '\\_\\_forensic\\_\\_/sections/%' ESCAPE '\\' THEN 0
                          WHEN file_path LIKE '\\_\\_forensic\\_\\_/%' ESCAPE '\\' THEN 0
                          WHEN file_path ILIKE '%/SAM' THEN 0
                          WHEN file_path ILIKE '%Security.evtx' THEN 0
                          WHEN file_path ILIKE '%NTUSER.DAT' THEN 1
                          WHEN file_path ILIKE 'Users/%' THEN 2 ELSE 3 END,
                     length(coalesce(content,'')) DESC
            LIMIT :lim""",
        params,
    )
    return [dict(r) for r in rows]


def _parse_result_search(db, query: str, *, job_id: str, limit: int = 30) -> list[dict]:
    """Search structured parser output so answers are not limited to already-chunked text files."""
    tokens = [t for t in re.findall(r"[A-Za-z0-9_]{3,}", query) if t.lower() not in _STOP]
    # Always include forensic account terms for login/password questions
    if _USER_INTENT.search(query or ""):
        tokens = list(dict.fromkeys(tokens + [
            "last_logon", "password_last_set", "sam_user", "logon", "ProfileList", "4624",
        ]))
    if not tokens:
        return []

    clauses = []
    params: dict = {"jid": job_id, "lim": limit}
    for i, tok in enumerate(tokens[:8]):
        key = f"p{i}"
        params[key] = f"%{tok}%"
        clauses.append(f"apr.normalized::text ILIKE :{key}")
    where = " OR ".join(clauses)
    rows = fetchall(
        db,
        f"""SELECT ja.id::text AS id, ja.job_id, ja.file_path,
                  left(apr.normalized::text, 4000) AS content,
                  ja.encyclopedia_artifact_id AS artifact_id,
                  'evidence' AS chunk_type,
                  jsonb_build_object('from_parse', true, 'parser', apr.parser_name) AS metadata,
                  0.7 AS score
           FROM artifact_parse_results apr
           JOIN job_artifacts ja ON ja.id = apr.job_artifact_id
           WHERE ja.job_id = :jid AND ({where})
           ORDER BY CASE
             WHEN ja.file_path ILIKE '%/SAM' THEN 0
             WHEN ja.file_path ILIKE '%Security.evtx' THEN 0
             WHEN ja.file_path ILIKE '%SOFTWARE' THEN 1
             WHEN ja.file_path ILIKE '%NTUSER.DAT' THEN 1
             ELSE 2 END,
             length(apr.normalized::text) DESC
           LIMIT :lim""",
        params,
    )
    return [dict(r) for r in rows]


def _os_fact_boost(db, job_id: str) -> list[dict]:
    rows = fetchall(
        db,
        """SELECT id, job_id, file_path, content, artifact_id, chunk_type, metadata, 2.0 AS score
           FROM rag_chunks
           WHERE job_id=:jid AND (
             file_path = '__forensic__/windows_os'
             OR metadata->>'kind' = 'windows_os'
             OR file_path ILIKE '%/SOFTWARE'
             OR file_path ILIKE '%/SYSTEM'
             OR content ILIKE '%ProductName:%'
             OR content ILIKE '%Operating system:%'
           )
           LIMIT 15""",
        {"jid": job_id},
    )
    return [dict(r) for r in rows]


def _user_profile_boost(db, job_id: str) -> list[dict]:
    rows = fetchall(
        db,
        """SELECT id, job_id, file_path, content, artifact_id, chunk_type, metadata, 2.0 AS score
           FROM rag_chunks
           WHERE job_id=:jid AND (
             file_path = '__forensic__/windows_user_profiles'
             OR metadata->>'kind' = 'windows_users'
             OR file_path ILIKE '%/SAM'
             OR file_path ILIKE '%/winevt/Logs/Security.evtx'
             OR file_path ILIKE '%/NTUSER.DAT'
             OR content ILIKE '%Account timeline for%'
             OR content ILIKE '%Windows local account:%'
           )
           LIMIT 20""",
        {"jid": job_id},
    )
    return [dict(r) for r in rows]


def _rrf_fusion(lists: list[list[dict]], *, k: int | None = None, weights: list[float] | None = None) -> list[dict]:
    settings = get_settings()
    k = k or settings.retrieval_rrf_k
    weights = weights or [
        settings.retrieval_vector_weight,
        settings.retrieval_bm25_weight,
        settings.retrieval_bm25_weight,
        1.0,
        1.2,
    ]
    scores: dict[str, float] = {}
    items: dict[str, dict] = {}
    for wi, lst in enumerate(lists):
        w = weights[wi] if wi < len(weights) else 1.0
        for rank, item in enumerate(lst):
            cid = str(item.get("id") or item.get("chunk_id") or f"{wi}-{rank}")
            scores[cid] = scores.get(cid, 0) + w * (1 / (k + rank + 1))
            items[cid] = item
    ordered = sorted(scores.keys(), key=lambda x: scores[x], reverse=True)
    return [{**items[cid], "rrf_score": scores[cid]} for cid in ordered]


def _image_asset_search(db, query: str, *, job_id: str, limit: int = 20) -> list[dict]:
    """Lexical + optional CLIP search over rag_image_assets (image-evidence jobs)."""
    from app.db.sql_helpers import fetchall

    rows: list[dict] = []
    try:
        rows = fetchall(
            db,
            """SELECT id::text AS id, job_id::text AS job_id, filename AS file_path,
                      coalesce(ocr_text, '') AS content,
                      relative_path, root_label, sha256, thumbnail_uri,
                      ocr_confidence,
                      ts_rank(
                        to_tsvector('english', coalesce(ocr_text,'') || ' ' || coalesce(filename,'') || ' ' || coalesce(relative_path,'')),
                        plainto_tsquery('english', :q)
                      ) AS score
               FROM rag_image_assets
               WHERE job_id = CAST(:jid AS uuid)
                 AND (
                   to_tsvector('english', coalesce(ocr_text,'') || ' ' || coalesce(filename,'') || ' ' || coalesce(relative_path,''))
                     @@ plainto_tsquery('english', :q)
                   OR lower(filename) LIKE '%' || lower(:q) || '%'
                   OR lower(relative_path) LIKE '%' || lower(:q) || '%'
                 )
               ORDER BY score DESC NULLS LAST
               LIMIT :lim""",
            {"jid": job_id, "q": query, "lim": limit},
        )
    except Exception as exc:
        log.debug("image asset FTS skipped: %s", exc)
        return []

    out: list[dict] = []
    for r in rows or []:
        meta = {
            "modality": "image",
            "relative_path": r.get("relative_path"),
            "root_label": r.get("root_label"),
            "sha256": r.get("sha256"),
            "thumbnail_uri": r.get("thumbnail_uri"),
            "ocr_confidence": r.get("ocr_confidence"),
            "citation_kind": "image_evidence",
        }
        out.append(
            {
                "id": f"img:{r.get('id')}",
                "job_id": r.get("job_id"),
                "file_path": r.get("file_path") or r.get("relative_path"),
                "content": (r.get("content") or "")[:2000],
                "score": float(r.get("score") or 0.5),
                "chunk_type": "image_evidence",
                "metadata": meta,
            }
        )

    # Optional CLIP similarity arm when enabled
    try:
        from app.config import get_settings
        from app.services.image_embed import embed_query, model_fingerprint

        settings = get_settings()
        from app.services.forensic_serial_policy import serial_enabled
        if not serial_enabled() and getattr(settings, "rag_image_embed_enabled", False) and query.strip():
            qvec = embed_query(query)
            model_name, model_ver = model_fingerprint()
            vec_str = "[" + ",".join(f"{v:.8f}" for v in qvec) + "]"
            clip_rows = fetchall(
                db,
                """SELECT a.id::text AS id, a.job_id::text AS job_id, a.filename AS file_path,
                          left(coalesce(a.ocr_text,''), 2000) AS content,
                          a.relative_path, a.root_label, a.sha256, a.thumbnail_uri,
                          1 - (e.embedding <=> CAST(:emb AS vector)) AS score
                   FROM rag_image_embeddings e
                   JOIN rag_image_assets a ON a.id = e.image_id
                   WHERE a.job_id = CAST(:jid AS uuid)
                     AND e.modality = 'image'
                     AND e.model_name = :model
                     AND e.model_version = :ver
                   ORDER BY e.embedding <=> CAST(:emb AS vector)
                   LIMIT :lim""",
                {
                    "jid": job_id,
                    "emb": vec_str,
                    "model": model_name,
                    "ver": model_ver,
                    "lim": limit,
                },
            )
            for r in clip_rows or []:
                out.append(
                    {
                        "id": f"imgvec:{r.get('id')}",
                        "job_id": r.get("job_id"),
                        "file_path": r.get("file_path") or r.get("relative_path"),
                        "content": r.get("content") or "",
                        "score": float(r.get("score") or 0),
                        "chunk_type": "image_evidence",
                        "metadata": {
                            "modality": "image_vector",
                            "relative_path": r.get("relative_path"),
                            "root_label": r.get("root_label"),
                            "sha256": r.get("sha256"),
                            "thumbnail_uri": r.get("thumbnail_uri"),
                            "citation_kind": "image_evidence",
                        },
                    }
                )
    except Exception as exc:
        log.debug("image vector arm skipped: %s", exc)

    return out


def hybrid_retrieve(
    db,
    job_id: str,
    query: str,
    *,
    filters: dict | None = None,
    top_k: int = 10,
    schema_name: str | None = None,
    skip_vector: bool = False,
) -> list[dict]:
    from app.db.session import apply_firm_search_path
    from app.db.tenant import get_tenant_context

    filters = filters or {}
    schema = schema_name or (get_tenant_context().schema_name if get_tenant_context() else None)
    apply_firm_search_path(db, schema)

    # Prefer fast keyword / Postgres FTS first so UI does not hang on BGE-M3 load.
    search_k = max(top_k * 3, 30)
    ts_hits = _tsvector_search(db, query, job_id=job_id, limit=search_k)
    kw_hits = _keyword_search(db, query, job_id=job_id, limit=search_k)
    parse_hits = _parse_result_search(db, query, job_id=job_id, limit=search_k)
    bm25_os = search_bm25(query, job_id=job_id, size=search_k)
    os_hits = [{"id": h.get("id"), "content": h.get("content"), "score": h.get("score"), **h} for h in bm25_os]
    image_hits = _image_asset_search(db, query, job_id=job_id, limit=search_k)

    boost: list[dict] = []
    if _USER_INTENT.search(query or ""):
        try:
            from app.services.forensic_profile_index import (
                ensure_profile_fact_chunks,
                profile_chunk_has_accounts,
                _has_account_timeline_parsed,
            )

            if not profile_chunk_has_accounts(db, job_id):
                ensure_profile_fact_chunks(
                    db,
                    job_id,
                    refresh_critical=not _has_account_timeline_parsed(db, job_id),
                )
                db.flush()
        except Exception as exc:
            log.warning("Profile fact index failed: %s", exc)
            db.rollback()
            apply_firm_search_path(db, schema)
        boost = _user_profile_boost(db, job_id)
    elif _OS_INTENT.search(query or ""):
        try:
            from app.services.forensic_profile_index import (
                ensure_os_fact_chunks,
                profile_chunk_has_os,
            )

            ensure_os_fact_chunks(db, job_id, refresh_hives=not profile_chunk_has_os(db, job_id))
            db.flush()
        except Exception as exc:
            log.warning("OS fact index failed: %s", exc)
            db.rollback()
            apply_firm_search_path(db, schema)
            try:
                from app.services.forensic_profile_index import ensure_os_fact_chunks

                ensure_os_fact_chunks(db, job_id, refresh_hives=False)
                db.flush()
            except Exception as exc2:
                log.warning("OS fact fallback failed: %s", exc2)
        boost = _os_fact_boost(db, job_id)

    vector_hits: list[dict] = []
    indexing_gpu = _gpu_indexing_active(db, job_id)
    has_text_hits = bool(ts_hits or kw_hits or os_hits or boost or parse_hits)
    structured_intent = bool(
        _USER_INTENT.search(query or "")
        or _OS_INTENT.search(query or "")
        or _section_summary_intent(query or "")
    )
    from app.services.forensic_serial_policy import serial_enabled
    skip_vector = skip_vector or serial_enabled() or (structured_intent and has_text_hits)
    if not has_text_hits:
        if skip_vector:
            vector_hits = []
        else:
            vector_hits = _vector_search(db, query, job_id=job_id, limit=search_k)
    elif settings_want_vector() and not indexing_gpu and not skip_vector:
        # Skip optional vector while GPU is embedding — keyword/FTS hits are enough.
        try:
            vector_hits = _vector_search(db, query, job_id=job_id, limit=top_k)
        except Exception as exc:
            log.warning("Optional vector search failed: %s", exc)

    fused = _rrf_fusion(
        [boost or [], vector_hits, ts_hits, kw_hits, os_hits, parse_hits, image_hits],
        weights=[2.0, 1.0, 1.0, 1.0, 1.0, 1.3, 1.4],
    )[: top_k * 3]
    if boost:
        fused = boost + [c for c in fused if str(c.get("id")) not in {str(b.get("id")) for b in boost}]

    artifact_ids = [str(c.get("artifact_id")) for c in fused if c.get("artifact_id")]
    # Skip noisy graph stubs for count/inventory-style questions
    skip_graph = bool(re.search(r"\b(how\s+many|count|artifacts?\s+available)\b", query or "", re.I))
    if not skip_graph:
        try:
            driver = _get_driver()
            expanded = graph_expand(driver, artifact_ids[:10], hops=2) if driver else []
            for ex in expanded:
                fused.append({
                    "artifact_id": ex["id"],
                    "file_path": ex.get("file_path") or "",
                    "content": f"Graph related artifact {ex['id']}",
                    "score": 0.1,
                })
        except Exception as exc:
            log.warning("Graph expand skipped: %s", exc)

    # Drop empty graph stubs before rerank when better evidence exists
    if any((c.get("file_path") or "").strip() for c in fused):
        fused = [
            c for c in fused
            if not str(c.get("content") or "").startswith("Graph related artifact")
            or (c.get("file_path") or "").strip()
        ] or fused

    reranked = rerank_chunks(query, fused, top_k=max(top_k, 12))

    apply_firm_search_path(db, schema)
    execute(
        db,
        """INSERT INTO rag_retrieval_log (job_id, query, filters, retrieved_ids, rerank_scores)
           VALUES (:jid, :q, CAST(:f AS jsonb), CAST(:ids AS jsonb), CAST(:scores AS jsonb))""",
        {
            "jid": job_id,
            "q": query,
            "f": json.dumps(filters),
            "ids": json.dumps([str(c.get("id")) for c in reranked]),
            "scores": json.dumps([c.get("rerank_score") for c in reranked]),
        },
    )
    db.commit()
    return reranked


def settings_want_vector() -> bool:
    """Run vector search alongside keywords when not in tight CPU-only mode."""
    settings = get_settings()
    return (settings.rag_embedding_device or "").lower() in ("cuda", "gpu", "auto")
