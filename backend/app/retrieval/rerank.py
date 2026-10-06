"""Cross-encoder reranking (GPU when available)."""

from __future__ import annotations

import logging

log = logging.getLogger("rerank")

_reranker = None
_reranker_failed = False


def _get_reranker():
    global _reranker, _reranker_failed
    if _reranker_failed:
        return None
    if _reranker is not None:
        return _reranker
    try:
        from sentence_transformers import CrossEncoder

        _reranker = CrossEncoder("cross-encoder/ms-marco-MiniLM-L-6-v2")
        return _reranker
    except Exception as exc:
        log.warning("Reranker unavailable: %s", exc)
        _reranker_failed = True
        return None


def rerank_chunks(query: str, chunks: list[dict], *, top_k: int = 10) -> list[dict]:
    if not chunks:
        return []
    # Avoid loading CrossEncoder on every retrieve (slow on CPU / causes API timeouts).
    from app.config import get_settings

    settings = get_settings()
    use_ce = (getattr(settings, "rag_rerank_enabled", None) is True) or (
        str(getattr(settings, "rag_rerank_enabled", "")).lower() in ("1", "true", "yes")
    )
    # Fallback when setting missing: only use CE if model already warm
    model = _reranker if (_reranker is not None and not _reranker_failed) else None
    if use_ce and model is None:
        model = _get_reranker()
    if model is None:
        for i, c in enumerate(chunks):
            c["rerank_score"] = float(c.get("rrf_score") or c.get("score") or (1 - i * 0.01))
        chunks = sorted(chunks, key=lambda x: x.get("rerank_score", 0), reverse=True)
        return chunks[:top_k]

    pairs = [(query, (c.get("content") or "")[:512]) for c in chunks]
    scores = model.predict(pairs)
    for c, s in zip(chunks, scores):
        c["rerank_score"] = float(s)
    chunks.sort(key=lambda x: x.get("rerank_score", 0), reverse=True)
    return chunks[:top_k]
