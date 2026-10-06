"""Collect browser URL records from Chrome/Edge SQLite artifacts (AXIOM-style)."""

from __future__ import annotations

import logging
import os
import re
import sqlite3
import tempfile
import threading
import time
from typing import Any

from app.db.sql_helpers import fetchall, fetchone
from app.services.artifact_live_counts import _read_job_files

log = logging.getLogger("browser_url_inventory")

_CACHE_LOCK = threading.Lock()
_URL_RECORDS_CACHE: dict[str, tuple[float, list[dict[str, Any]]]] = {}
_URL_TOTALS_CACHE: dict[str, tuple[float, dict[str, int]]] = {}
_URL_JOB_LOCKS: dict[str, threading.Lock] = {}
_URL_CACHE_TTL_SEC = 1800.0


def _url_job_lock(job_id: str) -> threading.Lock:
    with _CACHE_LOCK:
        lock = _URL_JOB_LOCKS.get(job_id)
        if lock is None:
            lock = threading.Lock()
            _URL_JOB_LOCKS[job_id] = lock
        return lock

# Only real Chromium/Firefox/Safari history DBs — never whole User Data trees (those match
# DLLs / Safe Browsing stores and starve the LIMIT 80 slot so URL counts stay 0).
_BROWSER_SOURCE_SQL = """
    SELECT file_path, size_bytes FROM job_artifacts
    WHERE job_id=:j AND size_bytes > 512 AND size_bytes < 524288000 AND (
      lower(file_name) IN (
        'history', 'history-wal', 'history-journal',
        'history.db', 'browser2.db', 'bookmarks.db',
        'searchhistory.db', 'browserstate.db',
        'places.sqlite', 'places.sqlite-wal',
        'favicons', 'top sites', 'web data', 'cookies', 'login data'
      )
      OR file_path ~* '/(History|History-wal|History-journal|History\\.db|Browser2\\.db|Bookmarks\\.db|searchhistory\\.db|places\\.sqlite|places\\.sqlite-wal|Favicons|Top Sites|Web Data|Cookies|Login Data)$'
      OR (
        lower(replace(file_path, '\\\\', '/')) LIKE '%safari%'
        AND (
          lower(file_name) IN ('history.db', 'browserstate.db', 'history.plist', 'bookmarks.db')
          OR lower(file_name) LIKE '%history%.plist'
        )
      )
      OR (
        lower(replace(file_path, '\\\\', '/')) LIKE '%googlemobile%'
        AND lower(file_name) = 'searchhistory.db'
      )
    )
    AND file_path NOT ILIKE '%campaign_history%'
    AND file_path NOT ILIKE '%/Cache/%'
    AND file_path NOT ILIKE '%/Code Cache/%'
    AND file_path NOT ILIKE '%.dll'
    AND file_path NOT ILIKE '%.exe'
    AND file_path NOT ILIKE '%.bin'
    AND file_path NOT ILIKE '%.store%'
    AND file_path NOT ILIKE '%Safe Browsing%'
    ORDER BY size_bytes DESC
    LIMIT 160
"""

_URL_IN_TEXT_RE = re.compile(r"https?://[^\s<>\"'\\)]{4,500}", re.IGNORECASE)


_CONTENT_TYPE_BY_EXT: dict[str, str] = {
    ".pdf": "application/pdf",
    ".doc": "application/msword",
    ".docx": "application/vnd.openxmlformats-officedocument.wordprocessingml.document",
    ".xls": "application/vnd.ms-excel",
    ".xlsx": "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
    ".ppt": "application/vnd.ms-powerpoint",
    ".pptx": "application/vnd.openxmlformats-officedocument.presentationml.presentation",
    ".zip": "application/zip",
    ".rar": "application/vnd.rar",
    ".7z": "application/x-7z-compressed",
    ".jpg": "image/jpeg",
    ".jpeg": "image/jpeg",
    ".png": "image/png",
    ".gif": "image/gif",
    ".webp": "image/webp",
    ".heic": "image/heic",
    ".mp4": "video/mp4",
    ".mp3": "audio/mpeg",
    ".csv": "text/csv",
    ".json": "application/json",
    ".xml": "application/xml",
    ".html": "text/html",
    ".htm": "text/html",
    ".txt": "text/plain",
}


def infer_url_content_type(url: str) -> str:
    """Best-effort content type from URL path extension (browsers rarely store response MIME)."""
    try:
        from urllib.parse import urlparse, unquote

        path = unquote(urlparse(url).path or "").lower()
    except Exception:
        path = (url or "").lower()
    if not path or path.endswith("/"):
        return "text/html"
    # strip query-like suffixes already handled by urlparse; take last segment
    name = path.rsplit("/", 1)[-1]
    if "." not in name:
        return "text/html"
    ext = "." + name.rsplit(".", 1)[-1]
    if len(ext) > 8:
        return "text/html"
    if ext in _CONTENT_TYPE_BY_EXT:
        return _CONTENT_TYPE_BY_EXT[ext]
    if ext in {".php", ".asp", ".aspx", ".jsp", ".cgi"}:
        return "text/html"
    # Unknown short extension — still treat as a web page by default.
    return "text/html"


def content_type_short_label(content_type: str | None) -> str:
    """Human label for examiners (HTML page, PDF, image, …)."""
    ct = (content_type or "text/html").lower().strip()
    if ct == "text/html":
        return "Web page"
    if ct == "application/pdf":
        return "PDF"
    if ct.startswith("image/"):
        return "Image"
    if ct.startswith("video/"):
        return "Video"
    if ct.startswith("audio/"):
        return "Audio"
    if "spreadsheet" in ct or "excel" in ct or ct == "text/csv":
        return "Spreadsheet"
    if "word" in ct or "msword" in ct:
        return "Document"
    if "presentation" in ct or "powerpoint" in ct:
        return "Presentation"
    if "zip" in ct or "compressed" in ct or "rar" in ct:
        return "Archive"
    if ct in {"application/json", "application/xml", "text/plain"}:
        return "Data file"
    return ct.split("/")[-1].upper() if "/" in ct else ct


def _profile_key(path: str) -> str:
    """Compatibility profile label; occurrence deduplication still keeps each source."""
    normalized = path.replace("\\", "/").lower()
    snapshot = re.search(r"(?:^|/)(snapshots/[^/]+)(?:/|$)", normalized)
    if snapshot:
        return snapshot.group(1)
    return normalized.rsplit("/", 1)[0]


def infer_browser_label(path: str) -> str:
    low = (path or "").replace("\\", "/").lower()
    if "safari" in low:
        return "Safari"
    if "firefox" in low or "mozilla" in low:
        return "Firefox"
    if "edge" in low or ("microsoft" in low and "edge" in low):
        return "Edge"
    if "brave" in low:
        return "Brave"
    if "opera" in low:
        return "Opera"
    if "vivaldi" in low:
        return "Vivaldi"
    if "chrome" in low or "chromium" in low or "/history" in low:
        return "Chrome"
    if low.endswith(".url"):
        return "Internet Shortcut"
    if "carved" in low:
        return "Carved"
    return "Browser"


def _chrome_time_to_iso(raw: Any) -> str | None:
    """Chrome/WebKit time (µs since 1601-01-01) → ISO-8601 Z."""
    try:
        from datetime import datetime, timedelta, timezone

        n = int(raw)
        if n <= 0:
            return None
        if n > 10_000_000_000_000:  # µs WebKit
            seconds = (n / 1_000_000.0) - 11_644_473_600
        elif n > 10_000_000_000:  # ms
            seconds = n / 1000.0
        else:
            seconds = float(n)
        dt = datetime(1970, 1, 1, tzinfo=timezone.utc) + timedelta(seconds=seconds)
        if dt.year < 1995 or dt.year > 2100:
            return None
        return dt.isoformat().replace("+00:00", "Z")
    except Exception:
        return None


def normalize_extracted_url(url: str) -> str | None:
    """Strip chat punctuation / WhatsApp trailing junk so URL variants collapse."""
    u = (url or "").strip()
    if not u:
        return None
    # Trim common trailing punctuation and WhatsApp/markdown leftovers (*, _), brackets.
    u = u.rstrip(".,;:!?)>]}\"'\t\r\n")
    while u and u[-1] in "*_~`":
        u = u[:-1]
    u = u.rstrip(".,;:!?)>]}\"'\t\r\n")
    if not u.lower().startswith("http://") and not u.lower().startswith("https://"):
        return None
    # Drop zero-width / control chars sometimes embedded in message text.
    u = re.sub(r"[\u200b-\u200f\u202a-\u202e]", "", u)
    if len(u) < 10 or "*" in u or " " in u:
        return None
    return u


def _enrich_url_record(
    rec: dict[str, Any], *, source: str, record_origin: str | None = None
) -> dict[str, Any]:
    url = normalize_extracted_url(str(rec.get("url") or "")) or ""
    out = {
        "url": url,
        "visit_count": max(int(rec.get("visit_count") or 0), 1),
        "source": rec.get("source") or source,
        "title": (str(rec.get("title") or "").strip() or None),
        "last_visit": rec.get("last_visit") or None,
        "browser": rec.get("browser") or infer_browser_label(source),
        "content_type": rec.get("content_type") or infer_url_content_type(url),
        "record_origin": rec.get("record_origin") or record_origin or "browser_history",
    }
    return out


def _inventory_url_limit() -> int:
    from app.config import get_settings

    return max(int(getattr(get_settings(), "browser_inventory_url_limit", 50_000) or 50_000), 100)


def _inventory_max_db_bytes() -> int:
    from app.config import get_settings

    return max(int(getattr(get_settings(), "browser_inventory_max_db_bytes", 80_000_000) or 80_000_000), 1_000_000)


def _extract_chrome_history(cur: sqlite3.Cursor) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    by_url: dict[str, dict[str, Any]] = {}
    limit = _inventory_url_limit()
    try:
        cur.execute(
            """SELECT u.url, u.title, u.visit_count, u.last_visit_time
               FROM urls u
               WHERE u.url IS NOT NULL AND length(u.url) > 7
               ORDER BY u.last_visit_time DESC NULLS LAST, u.visit_count DESC NULLS LAST
               LIMIT ?""",
            (limit,),
        )
        for url, title, visit_count, last_visit in cur.fetchall():
            url_s = str(url)
            prev = by_url.get(url_s)
            visits = max(int(visit_count or 0), 1)
            rec = {
                "url": url_s,
                "title": (str(title).strip() if title else None),
                "visit_count": visits,
                "last_visit": _chrome_time_to_iso(last_visit),
            }
            if not prev or visits >= int(prev.get("visit_count") or 0):
                by_url[url_s] = rec
    except sqlite3.Error:
        by_url = {}
    if not by_url:
        try:
            cur.execute(
                """SELECT u.url, u.visit_count FROM urls u
                   WHERE u.url IS NOT NULL AND length(u.url) > 7
                   ORDER BY u.visit_count DESC NULLS LAST
                   LIMIT ?""",
                (limit,),
            )
            for url, visit_count in cur.fetchall():
                url_s = str(url)
                by_url[url_s] = {
                    "url": url_s,
                    "visit_count": max(int(visit_count or 0), 1),
                    "title": None,
                    "last_visit": None,
                }
        except sqlite3.Error:
            pass
    try:
        cur.execute(
            """SELECT u.url, COUNT(v.rowid) FROM urls u
               JOIN visits v ON v.url = u.id
               WHERE u.url IS NOT NULL AND length(u.url) > 7
               GROUP BY u.url
               ORDER BY COUNT(v.rowid) DESC
               LIMIT ?""",
            (limit,),
        )
        for url, visits in cur.fetchall():
            url_s = str(url)
            prev = by_url.get(url_s) or {"url": url_s, "visit_count": 1}
            prev["visit_count"] = max(int(visits or 0), int(prev.get("visit_count") or 0), 1)
            by_url[url_s] = prev
    except sqlite3.Error:
        pass
    rows.extend(by_url.values())
    return rows


def _extract_firefox_places(cur: sqlite3.Cursor) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    limit = _inventory_url_limit()
    try:
        cur.execute(
            """SELECT p.url, p.title, p.visit_count, p.last_visit_date
               FROM moz_places p
               WHERE p.url IS NOT NULL AND length(p.url) > 7
               ORDER BY p.last_visit_date DESC NULLS LAST, p.visit_count DESC NULLS LAST
               LIMIT ?""",
            (limit,),
        )
        for url, title, visits, last_visit in cur.fetchall():
            # Firefox last_visit_date is µs since Unix epoch.
            last_iso = None
            try:
                from datetime import datetime, timezone

                n = int(last_visit or 0)
                if n > 0:
                    last_iso = datetime.fromtimestamp(n / 1_000_000.0, tz=timezone.utc).isoformat().replace(
                        "+00:00", "Z"
                    )
            except Exception:
                last_iso = None
            rows.append(
                {
                    "url": str(url),
                    "title": (str(title).strip() if title else None),
                    "visit_count": max(int(visits or 0), 1),
                    "last_visit": last_iso,
                }
            )
    except sqlite3.Error:
        try:
            cur.execute(
                """SELECT p.url, p.visit_count FROM moz_places p
                   WHERE p.url IS NOT NULL AND length(p.url) > 7
                   ORDER BY p.visit_count DESC NULLS LAST
                   LIMIT ?""",
                (limit,),
            )
            for url, visits in cur.fetchall():
                rows.append({"url": str(url), "visit_count": max(int(visits or 0), 1)})
        except sqlite3.Error:
            pass
    return rows


def _extract_safari_history(cur: sqlite3.Cursor) -> list[dict[str, Any]]:
    """iOS/macOS Safari History.db (history_items / history_visits)."""
    rows: list[dict[str, Any]] = []
    limit = _inventory_url_limit()
    try:
        cur.execute(
            """SELECT i.url, i.title, COUNT(v.id) AS visits, MAX(v.visit_time) AS last_visit
               FROM history_items i
               LEFT JOIN history_visits v ON v.history_item = i.id
               WHERE i.url IS NOT NULL AND length(i.url) > 7
               GROUP BY i.id
               ORDER BY last_visit DESC NULLS LAST
               LIMIT ?""",
            (limit,),
        )
        for url, title, visits, last_visit in cur.fetchall():
            last_iso = None
            try:
                from datetime import datetime, timedelta, timezone

                n = float(last_visit or 0)
                if n > 0:
                    # Safari Core Data time: seconds since 2001-01-01
                    dt = datetime(2001, 1, 1, tzinfo=timezone.utc) + timedelta(seconds=n)
                    last_iso = dt.isoformat().replace("+00:00", "Z")
            except Exception:
                last_iso = None
            rows.append(
                {
                    "url": str(url),
                    "title": (str(title).strip() if title else None),
                    "visit_count": max(int(visits or 0), 1),
                    "last_visit": last_iso,
                    "browser": "Safari",
                }
            )
    except sqlite3.Error:
        try:
            cur.execute(
                """SELECT url, title FROM history_items
                   WHERE url IS NOT NULL AND length(url) > 7 LIMIT ?""",
                (limit,),
            )
            for url, title in cur.fetchall():
                rows.append(
                    {
                        "url": str(url),
                        "title": (str(title).strip() if title else None),
                        "visit_count": 1,
                        "browser": "Safari",
                    }
                )
        except sqlite3.Error:
            pass
    return rows


def _extract_favicons(cur: sqlite3.Cursor) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    limit = _inventory_url_limit()
    try:
        cur.execute(
            "SELECT page_url FROM icon_mapping WHERE page_url IS NOT NULL AND length(page_url) > 7 LIMIT ?",
            (limit,),
        )
        for (url,) in cur.fetchall():
            rows.append({"url": str(url), "visit_count": 1})
    except sqlite3.Error:
        pass
    try:
        cur.execute(
            "SELECT url FROM favicons WHERE url IS NOT NULL AND length(url) > 7 LIMIT ?",
            (limit,),
        )
        for (url,) in cur.fetchall():
            rows.append({"url": str(url), "visit_count": 1})
    except sqlite3.Error:
        pass
    return rows


def _extract_top_sites(cur: sqlite3.Cursor) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    limit = _inventory_url_limit()
    for col in ("url", "url_title"):
        try:
            cur.execute(
                f"SELECT {col} FROM top_sites WHERE {col} IS NOT NULL AND length({col}) > 7 LIMIT ?",
                (limit,),
            )
            for (url,) in cur.fetchall():
                if str(url).startswith("http"):
                    rows.append({"url": str(url), "visit_count": 1})
        except sqlite3.Error:
            pass
    return rows


def _extract_web_data(cur: sqlite3.Cursor) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    limit = _inventory_url_limit()
    for sql in (
        "SELECT url FROM urls WHERE url IS NOT NULL AND length(url) > 7 LIMIT ?",
        "SELECT url FROM autofill WHERE url IS NOT NULL AND length(url) > 7 LIMIT ?",
    ):
        try:
            cur.execute(sql, (limit,))
            for (url,) in cur.fetchall():
                rows.append({"url": str(url), "visit_count": 1})
        except sqlite3.Error:
            pass
    return rows


def _extract_google_search_history(cur: sqlite3.Cursor) -> list[dict[str, Any]]:
    """Google app searchhistory.db (browse_history_v2 / search_history)."""
    rows: list[dict[str, Any]] = []
    limit = _inventory_url_limit()
    try:
        cur.execute(
            """SELECT scheme, host, path, query, title, hitcount, accessed
               FROM browse_history_v2
               WHERE host IS NOT NULL AND length(host) > 1
               ORDER BY accessed DESC NULLS LAST
               LIMIT ?""",
            (limit,),
        )
        for scheme, host, path, query, title, hits, accessed in cur.fetchall():
            sch = (str(scheme or "https").rstrip(":/") or "https")
            url = f"{sch}://{host}{path or ''}"
            if query:
                url = f"{url}?{query}"
            rows.append(
                {
                    "url": url,
                    "title": (str(title).strip() if title else None),
                    "visit_count": max(int(hits or 0), 1),
                    "browser": "Google App",
                }
            )
    except sqlite3.Error:
        pass
    try:
        cur.execute(
            """SELECT query, suggestnav_url, hitcount
               FROM search_history
               WHERE (suggestnav_url IS NOT NULL AND length(suggestnav_url) > 7)
                  OR (query IS NOT NULL AND length(query) > 1)
               LIMIT ?""",
            (limit,),
        )
        for query, nav_url, hits in cur.fetchall():
            url = str(nav_url or "").strip()
            if not url.startswith("http") and query:
                from urllib.parse import quote_plus

                url = f"https://www.google.com/search?q={quote_plus(str(query))}"
            if url.startswith("http"):
                rows.append(
                    {
                        "url": url,
                        "title": str(query or "")[:120] or None,
                        "visit_count": max(int(hits or 0), 1),
                        "browser": "Google App",
                    }
                )
    except sqlite3.Error:
        pass
    return rows


def _extract_bookmarks_db(cur: sqlite3.Cursor) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    limit = min(_inventory_url_limit(), 20_000)
    for sql in (
        "SELECT url, title FROM bookmarks WHERE url IS NOT NULL AND length(url) > 7 LIMIT ?",
        "SELECT url, title FROM bookmark WHERE url IS NOT NULL AND length(url) > 7 LIMIT ?",
    ):
        try:
            cur.execute(sql, (limit,))
            for url, title in cur.fetchall():
                rows.append(
                    {
                        "url": str(url),
                        "title": (str(title).strip() if title else None),
                        "visit_count": 1,
                        "browser": "Safari Bookmarks",
                    }
                )
            if rows:
                break
        except sqlite3.Error:
            continue
    return rows


def extract_url_records_from_sqlite(data: bytes, path: str) -> list[dict[str, Any]]:
    """Parse one browser SQLite artifact into normalized URL records."""
    low = path.replace("\\", "/").lower()
    base = low.rsplit("/", 1)[-1]
    with tempfile.NamedTemporaryFile(suffix=".db", delete=False) as tmp:
        tmp.write(data)
        tmp_path = tmp.name
    out: list[dict[str, Any]] = []
    try:
        conn = sqlite3.connect(f"file:{tmp_path}?mode=ro", uri=True)
        cur = conn.cursor()
        if base == "searchhistory.db" or "searchhistory" in base:
            out.extend(_extract_google_search_history(cur))
        elif "places.sqlite" in base or "firefox" in low or "mozilla" in low:
            out.extend(_extract_firefox_places(cur))
        elif base == "bookmarks.db" or ("safari" in low and "bookmark" in low):
            out.extend(_extract_bookmarks_db(cur))
        elif base in {"history.db", "browser2.db", "browserstate.db"} or (
            "safari" in low and "history" in low
        ):
            out.extend(_extract_safari_history(cur))
            if not out:
                out.extend(_extract_chrome_history(cur))
        elif "history" in base or base == "history" or low.endswith("/history"):
            out.extend(_extract_chrome_history(cur))
            if not out:
                out.extend(_extract_safari_history(cur))
        if "favicons" in low:
            out.extend(_extract_favicons(cur))
        if "top sites" in low:
            out.extend(_extract_top_sites(cur))
        if "web data" in low:
            out.extend(_extract_web_data(cur))
        if "cookies" in low and "history" not in low:
            out.extend(_extract_web_data(cur))
        conn.close()
    except sqlite3.Error as exc:
        log.debug("browser sqlite parse failed %s: %s", path[-80:], exc)
    finally:
        try:
            os.unlink(tmp_path)
        except OSError:
            pass
    return [_enrich_url_record(rec, source=path) for rec in out]


def _collect_urls_from_message_stores(db, job_id: str) -> list[dict[str, Any]]:
    """Recover http(s) links embedded in SMS / WhatsApp message text (when Safari History is absent)."""
    rows = fetchall(
        db,
        """SELECT file_path, size_bytes FROM job_artifacts
           WHERE job_id=:j AND size_bytes > 1024 AND size_bytes < 524288000 AND (
             lower(file_name) IN ('sms.db', 'chatstorage.sqlite', 'msgstore.db')
             OR file_path ILIKE '%/Library/SMS/sms.db'
             OR file_path ILIKE '%ChatStorage.sqlite'
             OR file_path ILIKE '%/msgstore.db'
           )
           ORDER BY size_bytes DESC NULLS LAST
           LIMIT 12""",
        {"j": job_id},
    )
    if not rows:
        return []
    contents = _read_job_files(db, job_id, rows, max_bytes=_inventory_max_db_bytes())
    out: list[dict[str, Any]] = []
    seen: set[str] = set()
    for row in rows:
        path = (row.get("file_path") or "").replace("\\", "/")
        data = contents.get(path)
        if not data or not data[:16].startswith(b"SQLite format"):
            continue
        low = path.lower()
        browser = "WhatsApp link" if "whatsapp" in low or "chatstorage" in low else "SMS/iMessage link"
        tmp = tempfile.NamedTemporaryFile(suffix=".db", delete=False)
        try:
            tmp.write(data)
            tmp.close()
            conn = sqlite3.connect(f"file:{tmp.name}?mode=ro", uri=True)
            cur = conn.cursor()
            queries = [
                "SELECT text FROM message WHERE text LIKE '%http%' LIMIT 8000",
                "SELECT ZTEXT FROM ZWAMESSAGE WHERE ZTEXT LIKE '%http%' LIMIT 8000",
                "SELECT body FROM message WHERE body LIKE '%http%' LIMIT 8000",
            ]
            for sql in queries:
                try:
                    cur.execute(sql)
                except sqlite3.Error:
                    continue
                for (text,) in cur.fetchall():
                    if not text:
                        continue
                    for match in _URL_IN_TEXT_RE.findall(str(text)):
                        url = normalize_extracted_url(match)
                        if not url:
                            continue
                        key = url.lower().rstrip("/")
                        if key in seen:
                            continue
                        seen.add(key)
                        out.append(
                            {
                                "url": url,
                                "visit_count": 1,
                                "source": path,
                                "browser": browser,
                                "title": None,
                            }
                        )
                        if len(out) >= 20_000:
                            break
                if len(out) >= 20_000:
                    break
            conn.close()
        except Exception as exc:
            log.debug("message URL extract failed %s: %s", path[-60:], exc)
        finally:
            try:
                os.unlink(tmp.name)
            except OSError:
                pass
    return out


def clear_browser_url_cache(job_id: str | None = None) -> None:
    with _CACHE_LOCK:
        if job_id:
            _URL_RECORDS_CACHE.pop(job_id, None)
            _URL_TOTALS_CACHE.pop(job_id, None)
        else:
            _URL_RECORDS_CACHE.clear()
            _URL_TOTALS_CACHE.clear()


def _collect_internet_shortcut_urls(db, job_id: str) -> list[dict[str, Any]]:
    """Internet Shortcut (.url) files — often hold social/chat landing URLs."""
    rows = fetchall(
        db,
        """SELECT file_path, size_bytes FROM job_artifacts
           WHERE job_id=:j AND size_bytes > 20 AND size_bytes < 65536 AND (
             lower(coalesce(extension,''))='.url'
             OR file_path ILIKE '%.url'
           )
           ORDER BY size_bytes DESC NULLS LAST
           LIMIT 400""",
        {"j": job_id},
    )
    if not rows:
        return []
    contents = _read_job_files(db, job_id, rows, max_bytes=65_536)
    out: list[dict[str, Any]] = []
    for row in rows:
        path = (row.get("file_path") or "").replace("\\", "/")
        data = contents.get(path) or b""
        if not data:
            continue
        try:
            text = data.decode("utf-8", errors="ignore")
        except Exception:
            continue
        for line in text.splitlines():
            if line.lower().startswith("url="):
                url = line.split("=", 1)[1].strip()
                if url.startswith("http"):
                    out.append({"url": url, "visit_count": 1, "source": path})
                break
    return out


def _browser_source_origin(path: str) -> str:
    low = (path or "").replace("\\", "/").lower()
    base = low.rsplit("/", 1)[-1]
    if base in {"history", "history.db", "places.sqlite", "browser2.db", "browserstate.db", "searchhistory.db"}:
        return "browser_history"
    if "history" in base and not base.endswith(("-wal", "-journal")):
        return "browser_history"
    if base.endswith(("-wal", "-journal")) or "history-wal" in base or "history-journal" in base:
        return "browser_history_recovered"
    return "browser_aux"


def collect_job_browser_url_records(db, job_id: str) -> list[dict[str, Any]]:
    """Scan URL-bearing sources with provenance-aware de-duplication.

    A URL in Chrome/Edge/Firefox profile A is a different occurrence source from
    the same URL in profile B. The old implementation globally collapsed both and
    kept only MAX(visit_count), losing valid visits. Conversely, bookmark/message/
    carved URLs are not browser-visit records and must not inflate visit counts.
    """
    from app.services.forensic_serial_policy import serial_enabled
    if serial_enabled():
        from app.services.forensic_priority_evidence import priority_record_table
        table = priority_record_table(db, job_id)
        if table:
            persisted = fetchall(db, f"""SELECT artifact_type,timestamp_utc,data,forensic FROM {table}
                WHERE job_id=:jid AND (source_domain='browser' OR data ? 'urls') ORDER BY artifact_id""", {"jid":job_id})
            control = fetchone(db,"SELECT to_regclass('pipeline_stage_runs') AS name")
            complete = False
            if control and control.get("name"):
                complete = bool(fetchone(db,"""SELECT 1 AS ok FROM pipeline_stage_runs WHERE job_id=:jid AND stage='parse'
                    AND status='done' AND EXISTS(SELECT 1 FROM pipeline_stage_runs WHERE job_id=:jid AND stage='media_review')""",{"jid":job_id}))
            if persisted or complete:
                merged = {}
                for row in persisted:
                    data,forensic = row["data"] or {},row["forensic"] or {}
                    source = forensic.get("source_path") or ""
                    urls = ([data["url"]] if isinstance(data.get("url"),str) else []) + list(data.get("urls") or [])
                    origin = "browser_history" if row["artifact_type"] in {"browser_url","browser_visit"} else "message_store" if data.get("application")=="whatsapp" else "browser_reference"
                    for url in urls:
                        norm = normalize_extracted_url(str(url))
                        if not norm:
                            continue
                        key = (origin,source,norm)
                        count = max(1,int(data.get("visit_count") or 1)) if origin=="browser_history" else 0
                        previous = merged.get(key)
                        if previous and int(previous.get("visit_count") or 0)>=count:
                            continue
                        merged[key] = _enrich_url_record({"url":norm,"title":data.get("title"),"visit_count":count,
                            "last_visit":str(row["timestamp_utc"] or ""),"browser":infer_browser_label(source)},source=source,record_origin=origin)
                return list(merged.values())
    now = time.monotonic()
    with _CACHE_LOCK:
        hit = _URL_RECORDS_CACHE.get(job_id)
        if hit and (now - hit[0]) < _URL_CACHE_TTL_SEC:
            return hit[1]

    rows = fetchall(db, _BROWSER_SOURCE_SQL, {"j": job_id})
    contents = _read_job_files(db, job_id, rows, max_bytes=_inventory_max_db_bytes())

    def _merge_rec(
        merged: dict[str, dict[str, Any]],
        rec: dict[str, Any],
        *,
        source: str,
        origin: str,
    ) -> None:
        url = normalize_extracted_url(str(rec.get("url") or ""))
        if not url:
            return
        source_norm = (source or str(rec.get("source") or "")).replace("\\", "/").lower()
        enriched = _enrich_url_record(
            {**rec, "url": url}, source=source, record_origin=origin
        )
        if not enriched.get("url"):
            return
        # Only collapse duplicates emitted from the same physical source and domain.
        # Independent browser profiles/databases remain independent occurrences.
        key = f"{origin}|{source_norm}|{url.lower().rstrip('/')}"
        visits = max(int(enriched.get("visit_count") or 0), 1)
        prev = merged.get(key)
        if not prev or visits > int(prev.get("visit_count") or 0):
            merged[key] = enriched
            return
        for field in ("title", "last_visit", "browser", "content_type", "source"):
            if not prev.get(field) and enriched.get(field):
                prev[field] = enriched[field]
        prev["visit_count"] = max(int(prev.get("visit_count") or 0), visits)

    merged: dict[str, dict[str, Any]] = {}
    for row in rows:
        path = (row.get("file_path") or "").replace("\\", "/")
        data = contents.get(path)
        if not data or len(data) < 512:
            continue
        origin = _browser_source_origin(path)
        for rec in extract_url_records_from_sqlite(data, path):
            _merge_rec(merged, rec, source=path, origin=origin)

    for rec in _collect_internet_shortcut_urls(db, job_id):
        _merge_rec(merged, rec, source=str(rec.get("source") or ""), origin="internet_shortcut")
    try:
        for rec in _collect_urls_from_message_stores(db, job_id):
            _merge_rec(merged, rec, source=str(rec.get("source") or ""), origin="message_store")
    except Exception as exc:
        log.debug("message-store URL merge failed job=%s: %s", job_id, exc)
    try:
        from app.services.signature_carve_inventory import carved_url_records
        for rec in carved_url_records(db, job_id):
            _merge_rec(merged, rec, source=str(rec.get("source") or "carved"), origin="recovered_url")
    except Exception:
        pass

    # WAL/journal strings are recovered records, not live History rows.
    for row in rows:
        path = (row.get("file_path") or "").replace("\\", "/")
        pl = path.lower()
        if "history-wal" not in pl and "history-journal" not in pl and not pl.endswith("-wal"):
            continue
        data = contents.get(path)
        if not data or len(data) < 32:
            continue
        try:
            from app.services.signature_carve_inventory import extract_urls_from_raw_bytes
            for rec in extract_urls_from_raw_bytes(data, source_path=path):
                _merge_rec(merged, rec, source=path, origin="browser_history_recovered")
        except Exception:
            pass

    records = list(merged.values())
    with _CACHE_LOCK:
        _URL_RECORDS_CACHE[job_id] = (time.monotonic(), records)
    return records


def gather_browsing_summary(
    db,
    job_id: str,
    *,
    sample_limit: int = 12,
) -> dict[str, Any]:
    """Short structured browsing summary for Artifacts board / reports."""
    from app.services.url_category_counts import classify_url_category

    records = collect_job_browser_url_records(db, job_id)
    # Report browsing metrics represent browser-history visit records only.
    # Recovered/WAL/message-store/bookmark URLs remain browsable evidence but are
    # separate count domains and must not inflate the primary visit counts.
    primary_records = [
        r for r in records if str(r.get("record_origin") or "browser_history") == "browser_history"
    ]
    by_category: dict[str, int] = {
        "web chat urls": 0,
        "social media urls": 0,
        "malware/phishing urls": 0,
        "pornography urls": 0,
        "dating site urls": 0,
        "other": 0,
    }
    by_content: dict[str, int] = {}
    by_browser: dict[str, int] = {}
    for rec in primary_records:
        url = str(rec.get("url") or "")
        visits = max(int(rec.get("visit_count") or 0), 1)
        cat = classify_url_category(url) or "other"
        by_category[cat] = by_category.get(cat, 0) + visits
        ct_label = content_type_short_label(rec.get("content_type"))
        by_content[ct_label] = by_content.get(ct_label, 0) + 1
        browser = str(rec.get("browser") or infer_browser_label(str(rec.get("source") or "")))
        by_browser[browser] = by_browser.get(browser, 0) + 1

    ranked = sorted(
        primary_records,
        key=lambda r: (-int(r.get("visit_count") or 0), str(r.get("url") or "")),
    )
    samples: list[dict[str, Any]] = []
    for rec in ranked[: max(int(sample_limit), 0)]:
        url = str(rec.get("url") or "")
        samples.append(
            {
                "url": url,
                "title": rec.get("title"),
                "visit_count": max(int(rec.get("visit_count") or 0), 1),
                "content_type": rec.get("content_type") or infer_url_content_type(url),
                "content_type_label": content_type_short_label(rec.get("content_type")),
                "browser": rec.get("browser") or infer_browser_label(str(rec.get("source") or "")),
                "last_visit": rec.get("last_visit"),
                "category": classify_url_category(url) or "other",
                "source": rec.get("source"),
            }
        )

    return {
        "total_urls": len(primary_records),
        "total_visits": sum(max(int(r.get("visit_count") or 0), 1) for r in primary_records),
        "recovered_or_auxiliary_urls": max(len(records) - len(primary_records), 0),
        "by_category": by_category,
        "by_content_type": dict(sorted(by_content.items(), key=lambda kv: (-kv[1], kv[0]))),
        "by_browser": dict(sorted(by_browser.items(), key=lambda kv: (-kv[1], kv[0]))),
        "samples": samples,
    }


def gather_browsing_summary_markdown(db, job_id: str, *, sample_limit: int = 10) -> str:
    """Compact markdown block for report sections (artifact summary / extraction / annexure)."""
    summary = gather_browsing_summary(db, job_id, sample_limit=sample_limit)
    total = int(summary.get("total_urls") or 0)
    if total <= 0:
        return (
            "### Browsing activity\n\n"
            "_No visited URLs were recovered from browser history on the examined device._\n"
        )

    by_cat = summary.get("by_category") or {}
    by_ct = summary.get("by_content_type") or {}
    by_br = summary.get("by_browser") or {}
    lines = [
        "### Browsing activity",
        "",
        (
            f"Recovered **{total:,}** distinct visited URL(s) "
            f"(**{int(summary.get('total_visits') or 0):,}** visit count total) "
            f"from browser history on the examined device."
        ),
        "",
        "| Category | Visits |",
        "| --- | ---: |",
        f"| Web Chat URLs | {int(by_cat.get('web chat urls') or 0):,} |",
        f"| Social Media URLs | {int(by_cat.get('social media urls') or 0):,} |",
        f"| Malware/Phishing URLs | {int(by_cat.get('malware/phishing urls') or 0):,} |",
        f"| Pornography URLs | {int(by_cat.get('pornography urls') or 0):,} |",
        f"| Dating Site URLs | {int(by_cat.get('dating site urls') or 0):,} |",
        f"| Other URLs | {int(by_cat.get('other') or 0):,} |",
        "",
    ]
    if by_ct:
        top_ct = ", ".join(f"{k} ({v})" for k, v in list(by_ct.items())[:6])
        lines.append(f"**Content types (top):** {top_ct}")
        lines.append("")
    if by_br:
        top_br = ", ".join(f"{k} ({v})" for k, v in list(by_br.items())[:5])
        lines.append(f"**Browsers:** {top_br}")
        lines.append("")

    samples = list(summary.get("samples") or [])
    if samples:
        lines.extend(
            [
                "| Sr. | URL | Type | Browser | Visits |",
                "| ---: | --- | --- | --- | ---: |",
            ]
        )
        for i, s in enumerate(samples, 1):
            url = str(s.get("url") or "")[:140]
            lines.append(
                f"| {i} | `{url}` | {s.get('content_type_label') or 'Web page'} | "
                f"{s.get('browser') or '—'} | {int(s.get('visit_count') or 1)} |"
            )
        lines.append("")
        lines.append(
            f"*Sample of {len(samples)} most-visited URL(s). Full list is available under Artifacts → Browser History.*"
        )
        lines.append("")
    return "\n".join(lines)


def compute_communication_url_totals(db, job_id: str) -> dict[str, int]:
    """One browser-history pass → all Communication URL category totals (cached per job).

    Uses the same ``collect_job_browser_url_records`` set as Artifacts browse so
    catalog counts always match listable evidence rows.
    """
    with _url_job_lock(job_id):
        now = time.monotonic()
        with _CACHE_LOCK:
            hit = _URL_TOTALS_CACHE.get(job_id)
            if hit and (now - hit[0]) < _URL_CACHE_TTL_SEC:
                return dict(hit[1])

        from app.services.url_category_counts import classify_url_category, count_url_records

        records = collect_job_browser_url_records(db, job_id)
        # Primary report values are browser-history visit records only. Bookmarks,
        # message-store links, and carved/WAL URLs are retained for evidence browse
        # but are separate count domains and must not be mixed into visit totals.
        visit_origins = frozenset({"browser_history"})
        totals = {
            "web chat urls": count_url_records(records, category="web chat urls", count_visits=True, allowed_origins=visit_origins),
            "social media urls": count_url_records(records, category="social media urls", count_visits=True, allowed_origins=visit_origins),
            "malware/phishing urls": count_url_records(records, category="malware/phishing urls", count_visits=True, allowed_origins=visit_origins),
            "pornography urls": count_url_records(records, category="pornography urls", count_visits=True, allowed_origins=visit_origins),
            "dating site urls": count_url_records(records, category="dating site urls", count_visits=True, allowed_origins=visit_origins),
        }
        totals["recovered url records"] = sum(
            1 for r in records
            if str(r.get("record_origin") or "") in {"recovered_url", "browser_history_recovered"}
        )
        # Keep unclassified HTTP volume for diagnostics (not shown in Section B).
        other = 0
        for rec in records:
            if str(rec.get("record_origin") or "browser_history") != "browser_history":
                continue
            if classify_url_category(str(rec.get("url") or "")) is None:
                other += max(int(rec.get("visit_count") or 0), 1)
        totals["other http urls"] = other
        with _CACHE_LOCK:
            _URL_TOTALS_CACHE[job_id] = (time.monotonic(), totals)
        return dict(totals)
