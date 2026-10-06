"""Bridge normalized mobile forensic artifacts into the shared RAG corpus."""

from __future__ import annotations

import json
import logging
from typing import Any

from app.db.sql_helpers import execute, fetchall, fetchone

log = logging.getLogger("mobile_forensic.rag")


def _clean(value: Any, *, max_len: int | None = None) -> str:
    if value is None:
        return ""
    if isinstance(value, (dict, list)):
        try:
            s = json.dumps(value, ensure_ascii=False, default=str)
        except Exception:
            s = str(value)
    else:
        s = str(value)
    text = s.replace("\x00", " ")
    return text if max_len is None else text[:max_len]


def artifact_to_rag_text(row: dict[str, Any]) -> str:
    data = row.get("data") or {}
    forensic = row.get("forensic") or {}
    if isinstance(data, str):
        try: data = json.loads(data)
        except Exception: data = {"value": data}
    if isinstance(forensic, str):
        try: forensic = json.loads(forensic)
        except Exception: forensic = {}

    ordered_keys = (
        "application", "artifact_family", "display_name", "address", "peer_identity",
        "conversation_id", "sender", "direction", "body", "text", "title", "url",
        "media_name", "media_path", "media_mime", "path", "name", "mime", "sha256",
        "latitude", "longitude", "status", "message_type", "call_type", "duration_seconds",
    )
    lines = [
        "Mobile forensic artifact",
        f"Artifact ID: {row.get('artifact_id')}",
        f"Type: {row.get('artifact_type')}",
        f"Domain: {row.get('source_domain')}",
        f"Time UTC: {row.get('timestamp_utc') or ''}",
        f"Evidence state: {row.get('state') or forensic.get('state') or ''}",
        f"Source path: {forensic.get('source_path') or ''}",
        f"Source table: {forensic.get('source_table') or ''}",
        f"Source row: {forensic.get('source_row_id') or ''}",
        f"Recovery source: {forensic.get('recovery_source') or ''}",
        f"Encrypted source path: {forensic.get('encrypted_source_path') or ''}",
        f"Encrypted source SHA256: {forensic.get('encrypted_source_sha256') or ''}",
        f"Decryption integrity: {forensic.get('decryption_integrity') or ''}",
    ]
    used: set[str] = set()
    if isinstance(data, dict):
        for key in ordered_keys:
            if key in data and data.get(key) not in (None, "", [], {}):
                lines.append(f"{key}: {_clean(data.get(key))}")
                used.add(key)
        # Preserve every parsed field; downstream 2500/800 chunking sets the
        # window size rather than truncating the evidence before chunking.
        for key, value in data.items():
            if key in used or value in (None, "", [], {}):
                continue
            lines.append(f"{key}: {_clean(value)}")
    return "\n".join(x for x in lines if x and not x.endswith(": "))


def index_mobile_artifacts_for_rag(db, job_id: str, *, force: bool = False, batch_size: int = 256,
                                   embed: bool | None = None, strict: bool = False) -> dict[str, Any]:
    """Index every normalized mobile artifact into ``rag_chunks``.

    Embeddings are generated when the normal RAG embedding setting is enabled. If
    the embedding model is unavailable, textual chunks are still inserted so lexical
    retrieval/report prompts can use the evidence.
    """
    from app.services.forensic_serial_policy import serial_enabled
    if serial_enabled() or (strict and embed is False):
        return _chunk_mobile_records(db, job_id, batch_size=batch_size)
    try:
        fetchone(db, "SELECT 1 FROM rag_chunks LIMIT 0")
    except Exception as exc:
        return {"status": "skipped", "reason": f"rag_chunks unavailable: {exc}", "indexed": 0}

    if force:
        try:
            execute(
                db,
                """DELETE FROM rag_chunks
                   WHERE job_id=:jid AND COALESCE(metadata->>'mobile_normalized','false')='true'""",
                {"jid": job_id},
            )
        except Exception:
            pass

    try:
        from app.config import get_settings
        settings = get_settings()
        embed_enabled = bool(getattr(settings, "rag_embedding_enabled", False)) if embed is None else bool(embed)
    except Exception:
        settings = None
        embed_enabled = False

    last_id = ""
    indexed = 0
    embedding_failures = 0
    while True:
        rows = fetchall(
            db,
            """SELECT artifact_id, artifact_type, source_domain,
                      timestamp_utc::text AS timestamp_utc, state, data, forensic
               FROM mobile_normalized_artifacts
               WHERE job_id=:jid AND artifact_id>:last
               ORDER BY artifact_id LIMIT :lim""",
            {"jid": job_id, "last": last_id, "lim": max(1, min(int(batch_size), 1000))},
        )
        if not rows:
            break
        batch = [dict(r) for r in rows]
        texts = [artifact_to_rag_text(r) for r in batch]
        vectors = None
        if embed_enabled and settings is not None and texts:
            try:
                from app.services.embedding_gpu import embed_texts
                vectors = embed_texts(
                    texts,
                    model_name=settings.rag_embedding_model,
                    device=settings.rag_embedding_device,
                    batch_size=settings.rag_batch_size,
                )
            except Exception as exc:
                embedding_failures += len(texts)
                vectors = None
                log.warning("mobile RAG embedding fallback to text-only: %s", exc)

        for idx, (row, content) in enumerate(zip(batch, texts)):
            aid = str(row["artifact_id"])
            path = f"mobile://artifact/{aid}"
            metadata = {
                "mobile_normalized": True,
                "mobile_artifact_id": aid,
                "artifact_type": row.get("artifact_type"),
                "source_domain": row.get("source_domain"),
                "state": row.get("state"),
            }
            vec = None
            if vectors is not None and idx < len(vectors) and vectors[idx] is not None:
                vec = "[" + ",".join(f"{float(v):.8f}" for v in vectors[idx]) + "]"
            try:
                execute(
                    db,
                    """INSERT INTO rag_chunks
                       (job_id, file_path, chunk_index, content, embedding, embedding_v2,
                        artifact_id, chunk_type, metadata)
                       SELECT :jid, :path, 0, :content, NULL, CAST(:emb AS vector),
                              :aid, 'evidence', CAST(:meta AS jsonb)
                       WHERE NOT EXISTS (
                         SELECT 1 FROM rag_chunks rc
                         WHERE rc.job_id=:jid AND rc.file_path=:path
                           AND COALESCE(rc.metadata->>'mobile_normalized','false')='true'
                       )""",
                    {
                        "jid": job_id, "path": path, "content": content,
                        "emb": vec, "aid": aid, "meta": json.dumps(metadata),
                    },
                )
                indexed += 1
            except Exception as exc:
                # Some installations may not expose embedding_v2 yet. Text-only fallback.
                try:
                    execute(
                        db,
                        """INSERT INTO rag_chunks (job_id, file_path, chunk_index, content, artifact_id, chunk_type, metadata)
                           SELECT :jid, :path, 0, :content, :aid, 'evidence', CAST(:meta AS jsonb)
                           WHERE NOT EXISTS (
                             SELECT 1 FROM rag_chunks rc WHERE rc.job_id=:jid AND rc.file_path=:path
                           )""",
                        {"jid": job_id, "path": path, "content": content, "aid": aid, "meta": json.dumps(metadata)},
                    )
                    indexed += 1
                except Exception:
                    log.debug("mobile RAG insert skipped %s: %s", aid, exc)
        last_id = str(batch[-1]["artifact_id"])
        try:
            db.flush()
        except Exception:
            pass

    return {"status": "ok", "indexed": indexed, "embedding_failures": embedding_failures, "embedding_enabled": embed_enabled}


def _chunk_mobile_records(db, job_id: str, *, batch_size: int = 256) -> dict[str, Any]:
    """Resumable text-only record chunking for lexical / full-text RAG search."""
    from psycopg2.extras import execute_values

    from app.services.dual_rag_index import _chunk_text
    from app.services.forensic_serial_policy import (
        CHUNK_OVERLAP,
        CHUNK_POLICY,
        CHUNK_SIZE,
    )
    from app.services.forensic_serial_pipeline import StageWaiting
    from app.services.job_control import pipeline_should_stop
    last = ""
    indexed = chunks = 0
    while True:
        if pipeline_should_stop(db, job_id):
            raise StageWaiting("Mobile RAG chunking paused by user")
        rows = fetchall(db, """SELECT m.artifact_id,m.artifact_type,m.source_domain,
            m.timestamp_utc::text AS timestamp_utc,m.state,m.data,m.forensic
            FROM mobile_normalized_artifacts m WHERE m.job_id=:jid AND m.artifact_id>:last
            AND NOT EXISTS (SELECT 1 FROM rag_chunks rc WHERE rc.job_id=:jid
                AND rc.metadata->>'mobile_artifact_id'=m.artifact_id
                AND rc.metadata->>'serial_pipeline'='true' AND rc.metadata->>'chunk_policy'=:policy)
            ORDER BY m.artifact_id LIMIT :lim""", {"jid": job_id, "last": last, "lim": max(1, min(batch_size, 1000)), "policy": CHUNK_POLICY})
        if not rows:
            break
        paths = [f"mobile://artifact/{row['artifact_id']}" for row in rows]
        execute(db, "DELETE FROM rag_chunks WHERE job_id=:jid AND file_path=ANY(:paths)", {"jid": job_id, "paths": paths})
        values = []
        for row, path in zip(rows, paths):
            text = artifact_to_rag_text(row) + "\n" + json.dumps({"forensic": row["forensic"]}, ensure_ascii=False, default=str)
            text = text.replace("\x00", "")
            metadata = json.dumps({"mobile_normalized": True, "mobile_artifact_id": str(row["artifact_id"]),
                                   "serial_pipeline": True, "chunk_policy": CHUNK_POLICY, "artifact_type": row["artifact_type"],
                                   "source_domain": row["source_domain"], "state": row["state"]})
            for idx, content in enumerate(_chunk_text(text, CHUNK_SIZE, CHUNK_OVERLAP)):
                values.append((job_id, path, idx, content, str(row["artifact_id"]), metadata))
        if values:
            with db.connection().connection.cursor() as cur:
                execute_values(cur, """INSERT INTO rag_chunks(job_id,file_path,chunk_index,content,artifact_id,chunk_type,metadata)
                    VALUES %s""", values, template="(%s,%s,%s,%s,%s,'evidence',%s::jsonb)", page_size=500)
        indexed += len(rows)
        chunks += len(values)
        last = str(rows[-1]["artifact_id"])
        db.commit()
    return {"status": "ok", "indexed": indexed, "chunks": chunks, "embedding_enabled": False}
