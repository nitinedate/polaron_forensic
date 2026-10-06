"""OpenSearch bulk sync for hybrid BM25 + kNN retrieval."""

from __future__ import annotations

import json
import logging
import urllib.error
import urllib.request

from app.config import get_settings

log = logging.getLogger("opensearch_sync")

_available: bool | None = None


def opensearch_available() -> bool:
    global _available
    if _available is not None:
        return _available
    settings = get_settings()
    try:
        req = urllib.request.Request(settings.opensearch_url, method="GET")
        with urllib.request.urlopen(req, timeout=5) as resp:
            _available = resp.status == 200
    except Exception:
        _available = False
    return _available


def _index_name(job_id: str | None) -> str:
    settings = get_settings()
    suffix = job_id or "encyclopedia"
    return f"{settings.opensearch_index_prefix}-{suffix}"


def bulk_index_chunks(chunks: list[dict], *, job_id: str | None = None) -> int:
    if not opensearch_available() or not chunks:
        return 0
    settings = get_settings()
    index = _index_name(job_id)
    lines: list[str] = []
    for c in chunks:
        doc = {k: (str(v) if hasattr(v, "hex") else v) for k, v in dict(c).items()}
        doc_id = str(doc.get("id") or doc.get("chunk_id") or "")
        if not doc_id:
            continue
        meta = {"index": {"_index": index, "_id": doc_id}}
        lines.append(json.dumps(meta))
        lines.append(json.dumps(doc, default=str))
    if not lines:
        return 0
    body = "\n".join(lines) + "\n"
    url = f"{settings.opensearch_url.rstrip('/')}/_bulk"
    req = urllib.request.Request(
        url,
        data=body.encode("utf-8"),
        headers={"Content-Type": "application/x-ndjson"},
        method="POST",
    )
    try:
        with urllib.request.urlopen(req, timeout=60) as resp:
            result = json.loads(resp.read().decode("utf-8"))
            if result.get("errors"):
                log.warning("OpenSearch bulk had errors")
            return len(chunks)
    except Exception as exc:
        log.warning("OpenSearch bulk failed: %s", exc)
        return 0


def search_bm25(query: str, *, job_id: str | None, size: int = 20) -> list[dict]:
    if not opensearch_available():
        return []
    settings = get_settings()
    index = _index_name(job_id)
    payload = {
        "size": size,
        "query": {"multi_match": {"query": query, "fields": ["content", "artifact_id", "file_path"]}},
    }
    url = f"{settings.opensearch_url.rstrip('/')}/{index}/_search"
    req = urllib.request.Request(
        url,
        data=json.dumps(payload).encode("utf-8"),
        headers={"Content-Type": "application/json"},
        method="POST",
    )
    try:
        with urllib.request.urlopen(req, timeout=15) as resp:
            data = json.loads(resp.read().decode("utf-8"))
            hits = data.get("hits", {}).get("hits", [])
            return [{"id": h["_id"], "score": h["_score"], **h.get("_source", {})} for h in hits]
    except urllib.error.HTTPError:
        return []
    except Exception as exc:
        log.debug("OpenSearch search failed: %s", exc)
        return []
