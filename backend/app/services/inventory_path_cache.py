"""OOM-safe path matching for inventory fallback counts.

Holding ~200k+ ``file_path`` strings in the Celery worker caused repeated
SIGKILL (OOM). Instead we stream paths once with a server-side cursor and
accumulate per-catalog-artifact counts in a compact dict.
"""

from __future__ import annotations

import logging
import re
import threading
from typing import Any, Callable

from sqlalchemy import text

log = logging.getLogger("inventory_path_cache")

ProgressCb = Callable[[str, int, int], None]

_lock = threading.Lock()
# job_id -> {artifact_id: path_match_count}
_FALLBACK_COUNTS: dict[str, dict[str, int]] = {}
_BUILDING: set[str] = set()


def clear_path_cache(job_id: str | None = None) -> None:
    with _lock:
        if job_id is None:
            _FALLBACK_COUNTS.clear()
            _BUILDING.clear()
        else:
            _FALLBACK_COUNTS.pop(job_id, None)
            _BUILDING.discard(job_id)


# Weak tokens that match huge swaths of a Windows disk image when used as ANY-match.
_STOP_TOKENS = frozenset({
    "file", "files", "data", "related", "analysis", "windows", "microsoft",
    "system", "user", "users", "program", "programs", "local", "roaming",
    "stored", "device", "devices", "media", "other", "items", "list", "lists",
    "record", "records", "entry", "entries", "log", "logs", "info", "information",
    "event", "events", "message", "messages", "chat", "chats", "active",
    "account", "accounts", "office", "document", "documents", "search",
    "history", "cache", "service", "services", "network", "networking",
})


def _tokens_from_name(name: str) -> frozenset[str]:
    """Meaningful path tokens for fallback matching (stopwords stripped)."""
    raw = [t for t in re.split(r"[^a-z0-9]+", (name or "").lower()) if len(t) > 3]
    toks = [t for t in raw if t not in _STOP_TOKENS]
    # If every token is a stopword, skip path matching entirely (return empty).
    # Falling back to "windows"/"files" previously matched tens of thousands of paths.
    return frozenset(toks[:4])


def ensure_job_artifact_paths(db, job_id: str) -> list[str]:
    """Compatibility shim — do NOT load paths into memory (OOM on large jobs)."""
    _ = (db, job_id)
    return []


def get_fallback_path_count(job_id: str, artifact_id: str) -> int | None:
    """Return precomputed fallback count, or None if index not built yet."""
    jid = str(job_id)
    with _lock:
        m = _FALLBACK_COUNTS.get(jid)
        if m is None:
            return None
        return int(m.get(str(artifact_id), 0))


def seed_fallback_path_counts(job_id: str, rows: list[dict[str, Any]] | None = None) -> dict[str, int]:
    """Mark path index ready with zeros — used by mobile jobs that skip Windows path-token scan."""
    counts: dict[str, int] = {}
    for r in rows or []:
        aid = str(r.get("artifact_id") or "")
        if aid:
            counts[aid] = 0
    jid = str(job_id)
    with _lock:
        _FALLBACK_COUNTS[jid] = counts
        _BUILDING.discard(jid)
    return counts


def ensure_fallback_path_counts(
    db,
    job_id: str,
    rows: list[dict[str, Any]],
    *,
    progress_cb: ProgressCb | None = None,
) -> dict[str, int]:
    """One streaming pass over job_artifacts — builds aid→count for path-token fallbacks.

    Memory stays O(catalog) (~hundreds of ints), never O(file count).
    """
    job_id = str(job_id)
    # Wait briefly if another thread is building — never treat "building" as empty index.
    for _ in range(600):  # up to ~60s
        with _lock:
            cached = _FALLBACK_COUNTS.get(job_id)
            if cached is not None:
                return cached
            if job_id not in _BUILDING:
                _BUILDING.add(job_id)
                break
        import time as _time

        _time.sleep(0.1)
    else:
        with _lock:
            cached = _FALLBACK_COUNTS.get(job_id)
            if cached is not None:
                return cached
            # Stale builder — take over.
            _BUILDING.add(job_id)

    aid_tokens: dict[str, frozenset[str]] = {}
    token_to_aids: dict[str, list[str]] = {}
    for r in rows:
        aid = str(r.get("artifact_id") or "")
        if not aid:
            continue
        toks = _tokens_from_name(str(r.get("artifact_name") or ""))
        # Cap tokens per artifact — long names explode matching cost.
        toks = frozenset(list(toks)[:4])
        if not toks:
            continue
        aid_tokens[aid] = toks
        for t in toks:
            token_to_aids.setdefault(t, []).append(aid)

    counts = {aid: 0 for aid in aid_tokens}
    if not aid_tokens:
        with _lock:
            _FALLBACK_COUNTS[job_id] = counts
            _BUILDING.discard(job_id)
        return counts

    all_tokens = list(token_to_aids.keys())
    scanned = 0
    # Batch tokens into compiled regexes — O(files × batches) instead of O(files × tokens).
    token_batches: list[tuple[re.Pattern[str], list[str]]] = []
    batch_size = 40
    for i in range(0, len(all_tokens), batch_size):
        chunk = all_tokens[i : i + batch_size]
        try:
            pat = re.compile("|".join(re.escape(t) for t in chunk))
            token_batches.append((pat, chunk))
        except re.error:
            for t in chunk:
                token_batches.append((re.compile(re.escape(t)), [t]))

    try:
        result = db.execute(
            text(
                """
                SELECT lower(file_path) AS p
                FROM job_artifacts
                WHERE job_id = :j
                  AND file_path IS NOT NULL
                  AND file_path <> ''
                  AND position('/windows/winsxs/' in lower(file_path)) = 0
                  AND position('/installer/' in lower(file_path)) = 0
                """
            ),
            {"j": job_id},
        )
        try:
            result = result.yield_per(4000)
        except Exception:
            pass

        for row in result:
            if hasattr(row, "_mapping"):
                path_l = str(row._mapping.get("p") or "")
            elif isinstance(row, (list, tuple)):
                path_l = str(row[0] or "")
            else:
                path_l = str(getattr(row, "p", row) or "")
            if not path_l:
                continue

            scanned += 1
            if progress_cb and scanned % 25000 == 0:
                progress_cb(f"Streaming path index ({scanned:,} files)", scanned, max(scanned, 1))

            # AND semantics: every artifact token must appear in the path.
            # (ANY-match on tokens like "files"/"windows" previously inflated
            # EML / Windows Mail / Encrypted Files into tens of thousands.)
            hit_tokens: set[str] = set()
            for pat, chunk in token_batches:
                if not pat.search(path_l):
                    continue
                for tok in chunk:
                    if tok in path_l:
                        hit_tokens.add(tok)
            if not hit_tokens:
                continue
            candidates: set[str] = set()
            for tok in hit_tokens:
                candidates.update(token_to_aids.get(tok) or ())
            for aid in candidates:
                required = aid_tokens.get(aid) or frozenset()
                if required and required.issubset(hit_tokens):
                    counts[aid] += 1

        if progress_cb:
            progress_cb(f"Path index ready ({scanned:,} files)", scanned, max(scanned, 1))
        log.info(
            "fallback path index ready job=%s files=%s catalog=%s tokens=%s",
            job_id,
            scanned,
            len(counts),
            len(all_tokens),
        )
        # Never cache an empty scan — inventory often races materialize and would
        # permanently zero every path-token fallback (USB/AmCache/Web Related/…).
        if scanned <= 0:
            log.warning(
                "fallback path index empty job=%s — not caching (materialize incomplete?)",
                job_id,
            )
            raise RuntimeError("job_artifacts empty during path index build")
    except Exception as exc:
        log.warning("fallback path index failed job=%s: %s", job_id, exc)
        with _lock:
            _BUILDING.discard(job_id)
            _FALLBACK_COUNTS.pop(job_id, None)
        return {}

    with _lock:
        _BUILDING.discard(job_id)
        _FALLBACK_COUNTS[job_id] = counts
    return counts


def count_paths_matching_tokens(job_id: str, tokens: list[str], db=None) -> int:
    """Deprecated — use get_fallback_path_count after ensure_fallback_path_counts."""
    _ = (job_id, tokens, db)
    return 0
