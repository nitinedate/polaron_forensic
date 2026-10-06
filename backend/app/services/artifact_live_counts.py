"""Count artifacts directly from stored files when parse results are incomplete."""

from __future__ import annotations

import json
import logging
import os
import re
import sqlite3
import tempfile
from typing import Any

from app.db.sql_helpers import fetchall, fetchone
from app.services.disk_manifest import build_index_map
from app.services.tar_cache import read_file_from_part, read_files_from_part

log = logging.getLogger("artifact_live_counts")

_HISTORY_SQL = """
    SELECT file_path, size_bytes, sha256 FROM job_artifacts
    WHERE job_id=:j AND size_bytes > 512 AND (
      lower(file_name) IN ('history', 'places.sqlite')
      OR file_path ILIKE '%/History'
      OR file_path ILIKE '%/places.sqlite'
    )
    AND file_path NOT ILIKE '%/Web Data'
    AND file_path NOT ILIKE '%campaign_history%'
    AND file_path NOT ILIKE '%-journal'
    ORDER BY size_bytes DESC
    LIMIT 2000
"""

_JUMPLIST_SQL = """
    SELECT file_path, size_bytes FROM job_artifacts
    WHERE job_id=:j AND file_path ILIKE '%.automaticDestinations-ms'
    AND size_bytes > 32
    ORDER BY size_bytes DESC NULLS LAST
    LIMIT 2000
"""

_HIVE_SQL = """
    SELECT file_path, size_bytes, sha256 FROM job_artifacts
    WHERE job_id=:j AND size_bytes > 4096 AND (
      lower(file_name) IN ('software', 'system', 'ntuser.dat', 'usrclass.dat')
      OR file_path ILIKE '%/SOFTWARE'
      OR file_path ILIKE '%/SYSTEM'
      OR file_path ILIKE '%/NTUSER.DAT'
    )
    ORDER BY size_bytes DESC
    LIMIT 80
"""


def _job_index_map(db, job_id: str) -> dict[str, str]:
    row = fetchone(db, "SELECT disk_source FROM jobs WHERE id=:id", {"id": job_id})
    manifest = row.get("disk_source") if row else {}
    if isinstance(manifest, str):
        try:
            manifest = json.loads(manifest)
        except json.JSONDecodeError:
            manifest = {}
    return build_index_map(manifest or {})


def _read_job_files(db, job_id: str, rows: list[dict], *, max_bytes: int | None = None) -> dict[str, bytes | None]:
    index_map = _job_index_map(db, job_id)
    by_part: dict[str, list[str]] = {}
    for row in rows:
        path = (row.get("file_path") or "").replace("\\", "/")
        part_uri = index_map.get(path)
        if part_uri:
            by_part.setdefault(part_uri, []).append(path)
    out: dict[str, bytes | None] = {}
    for part_uri, paths in by_part.items():
        if max_bytes is not None:
            out.update(read_files_from_part(part_uri, set(paths), max_bytes=max_bytes))
            continue
        if len(paths) == 1:
            out[paths[0]] = read_file_from_part(part_uri, paths[0])
        else:
            out.update(read_files_from_part(part_uri, set(paths)))
    return out


def _url_matches(url: str, patterns: list[re.Pattern]) -> bool:
    return bool(url and any(p.search(url) for p in patterns))


def _count_chrome_sqlite(data: bytes, patterns: list[re.Pattern], *, count_visits: bool) -> int:
    with tempfile.NamedTemporaryFile(suffix=".db", delete=False) as tmp:
        tmp.write(data)
        tmp_path = tmp.name
    total = 0
    try:
        from app.config import get_settings

        url_limit = max(int(getattr(get_settings(), "browser_inventory_url_limit", 50_000) or 50_000), 100)
        conn = sqlite3.connect(f"file:{tmp_path}?mode=ro", uri=True)
        cur = conn.cursor()
        visit_count_total = 0
        visits_table_total = 0
        try:
            cur.execute(
                "SELECT url, visit_count FROM urls WHERE url IS NOT NULL AND length(url) > 7 "
                "ORDER BY visit_count DESC NULLS LAST LIMIT ?",
                (url_limit,),
            )
            rows = cur.fetchall()
        except sqlite3.Error:
            rows = []
        for url, visit_count in rows:
            if not _url_matches(str(url), patterns):
                continue
            if count_visits:
                visit_count_total += max(int(visit_count or 0), 1)
            else:
                visit_count_total += 1
        if count_visits:
            try:
                cur.execute(
                    """SELECT u.url, COUNT(v.rowid) FROM urls u
                       JOIN visits v ON v.url = u.id
                       WHERE u.url IS NOT NULL AND length(u.url) > 7
                       GROUP BY u.url
                       ORDER BY COUNT(v.rowid) DESC
                       LIMIT ?""",
                    (url_limit,),
                )
                for url, visits in cur.fetchall():
                    if _url_matches(str(url), patterns):
                        visits_table_total += int(visits or 0)
            except sqlite3.Error:
                visits_table_total = 0
            total = max(visit_count_total, visits_table_total)
        else:
            total = visit_count_total
        conn.close()
    except sqlite3.Error:
        return 0
    finally:
        try:
            os.unlink(tmp_path)
        except OSError:
            pass
    return total


def _count_firefox_sqlite(data: bytes, patterns: list[re.Pattern], *, count_visits: bool) -> int:
    with tempfile.NamedTemporaryFile(suffix=".db", delete=False) as tmp:
        tmp.write(data)
        tmp_path = tmp.name
    total = 0
    try:
        conn = sqlite3.connect(f"file:{tmp_path}?mode=ro", uri=True)
        cur = conn.cursor()
        try:
            cur.execute(
                """SELECT p.url, p.visit_count FROM moz_places p
                   WHERE p.url IS NOT NULL AND length(p.url) > 7"""
            )
            rows = cur.fetchall()
        except sqlite3.Error:
            conn.close()
            return 0
        for url, visit_count in rows:
            if not _url_matches(str(url), patterns):
                continue
            total += max(int(visit_count or 0), 1) if count_visits else 1
        conn.close()
    except sqlite3.Error:
        return 0
    finally:
        try:
            os.unlink(tmp_path)
        except OSError:
            pass
    return total


def _browser_url_row_limit() -> int:
    from app.config import get_settings

    return max(int(getattr(get_settings(), "browser_inventory_url_limit", 50_000) or 50_000), 100)


def _count_chrome_sqlite_multi(
    data: bytes,
    pattern_groups: dict[str, list[re.Pattern]],
    *,
    count_visits: bool,
) -> dict[str, int]:
    totals = {name: 0 for name in pattern_groups}
    with tempfile.NamedTemporaryFile(suffix=".db", delete=False) as tmp:
        tmp.write(data)
        tmp_path = tmp.name
    try:
        conn = sqlite3.connect(f"file:{tmp_path}?mode=ro", uri=True)
        cur = conn.cursor()
        visit_count_totals = {name: 0 for name in pattern_groups}
        url_limit = _browser_url_row_limit()
        try:
            cur.execute(
                "SELECT url, visit_count FROM urls WHERE url IS NOT NULL AND length(url) > 7 "
                "ORDER BY visit_count DESC NULLS LAST LIMIT ?",
                (url_limit,),
            )
            rows = cur.fetchall()
        except sqlite3.Error:
            conn.close()
            return totals
        for url, visit_count in rows:
            url_s = str(url)
            for name, pats in pattern_groups.items():
                if not _url_matches(url_s, pats):
                    continue
                visit_count_totals[name] += max(int(visit_count or 0), 1) if count_visits else 1
        if count_visits:
            try:
                cur.execute(
                    """SELECT u.url, COUNT(v.rowid) FROM urls u
                       JOIN visits v ON v.url = u.id
                       WHERE u.url IS NOT NULL AND length(u.url) > 7
                       GROUP BY u.url
                       ORDER BY COUNT(v.rowid) DESC
                       LIMIT ?""",
                    (url_limit,),
                )
                visits_table_totals = {name: 0 for name in pattern_groups}
                for url, visits in cur.fetchall():
                    url_s = str(url)
                    for name, pats in pattern_groups.items():
                        if _url_matches(url_s, pats):
                            visits_table_totals[name] += int(visits or 0)
                for name in pattern_groups:
                    totals[name] = max(visit_count_totals[name], visits_table_totals[name])
            except sqlite3.Error:
                totals = visit_count_totals
        else:
            totals = visit_count_totals
        conn.close()
    except sqlite3.Error:
        return totals
    finally:
        try:
            os.unlink(tmp_path)
        except OSError:
            pass
    return totals


def count_browser_url_hits_multi(
    db,
    job_id: str,
    pattern_groups: dict[str, list[re.Pattern]],
    *,
    count_visits: bool = True,
) -> dict[str, int]:
    """Count URL hits for multiple named pattern groups in one history scan pass."""
    rows = fetchall(db, _HISTORY_SQL, {"j": job_id})
    from app.config import get_settings

    max_db = max(int(getattr(get_settings(), "browser_inventory_max_db_bytes", 512_000_000) or 512_000_000), 1_000_000)
    contents = _read_job_files(db, job_id, rows, max_bytes=max_db)
    totals = {name: 0 for name in pattern_groups}
    for row in rows:
        path = (row.get("file_path") or "").replace("\\", "/")
        data = contents.get(path)
        if not data or len(data) < 512:
            continue
        low = path.lower()
        if "firefox" in low or "mozilla" in low:
            # Firefox uses same chrome-style multi counter for now (moz_places variant omitted).
            part = _count_chrome_sqlite_multi(data, pattern_groups, count_visits=count_visits)
        else:
            part = _count_chrome_sqlite_multi(data, pattern_groups, count_visits=count_visits)
        for name, n in part.items():
            totals[name] += n
    return totals


def count_url_category_hits(
    db,
    job_id: str,
    category: str,
    *,
    count_visits: bool = True,
) -> dict[str, Any]:
    """Count browser history hits for a report URL category (web chat / social / malware)."""
    total = count_url_category_browser_scan(db, job_id, category, count_visits=count_visits)
    return {"count": total, "files_scanned": 0}


_URL_CATEGORY_KEYS = ("web chat urls", "social media urls", "malware/phishing urls")


def count_all_url_categories_browser_scan(
    db,
    job_id: str,
    *,
    count_visits: bool = True,
) -> dict[str, int]:
    """One pass over browser SQLite files → all Communication URL category totals."""
    from app.services.browser_url_inventory import _BROWSER_SOURCE_SQL

    totals = {k: 0 for k in _URL_CATEGORY_KEYS}
    rows = fetchall(db, _BROWSER_SOURCE_SQL, {"j": job_id})
    from app.config import get_settings

    max_db = max(int(getattr(get_settings(), "browser_inventory_max_db_bytes", 512_000_000) or 512_000_000), 1_000_000)
    contents = _read_job_files(db, job_id, rows, max_bytes=max_db)
    for row in rows:
        path = (row.get("file_path") or "").replace("\\", "/")
        data = contents.get(path)
        if not data or len(data) < 512:
            continue
        low = path.lower()
        if "firefox" in low or "mozilla" in low:
            part = _count_firefox_all_categories(data, count_visits=count_visits)
        else:
            part = _count_chrome_all_categories(data, count_visits=count_visits)
        for key, value in part.items():
            totals[key] = totals.get(key, 0) + int(value or 0)
    return totals


def count_url_category_browser_scan(
    db,
    job_id: str,
    category: str,
    *,
    count_visits: bool = True,
) -> int:
    """Scan all browser SQLite artifacts and classify URLs (AXIOM visit totals)."""
    target = (category or "").strip().lower()
    totals = count_all_url_categories_browser_scan(db, job_id, count_visits=count_visits)
    if target in totals:
        return int(totals.get(target) or 0)
    # Unknown category — fall back to single-category path for compatibility.
    from app.services.browser_url_inventory import _BROWSER_SOURCE_SQL

    rows = fetchall(db, _BROWSER_SOURCE_SQL, {"j": job_id})
    from app.config import get_settings

    max_db = max(int(getattr(get_settings(), "browser_inventory_max_db_bytes", 512_000_000) or 512_000_000), 1_000_000)
    contents = _read_job_files(db, job_id, rows, max_bytes=max_db)
    total = 0
    for row in rows:
        path = (row.get("file_path") or "").replace("\\", "/")
        data = contents.get(path)
        if not data or len(data) < 512:
            continue
        low = path.lower()
        if "firefox" in low or "mozilla" in low:
            total += _count_firefox_category(data, target, count_visits=count_visits)
        else:
            total += _count_chrome_category(data, target, count_visits=count_visits)
    return total


def _count_chrome_all_categories(data: bytes, *, count_visits: bool) -> dict[str, int]:
    from app.services.url_category_counts import classify_url_category

    totals = {k: 0 for k in _URL_CATEGORY_KEYS}
    visits_table = {k: 0 for k in _URL_CATEGORY_KEYS}
    with tempfile.NamedTemporaryFile(suffix=".db", delete=False) as tmp:
        tmp.write(data)
        tmp_path = tmp.name
    try:
        conn = sqlite3.connect(f"file:{tmp_path}?mode=ro", uri=True)
        cur = conn.cursor()
        url_limit = _browser_url_row_limit()
        try:
            cur.execute(
                "SELECT url, visit_count FROM urls WHERE url IS NOT NULL AND length(url) > 7 "
                "ORDER BY visit_count DESC NULLS LAST LIMIT ?",
                (url_limit,),
            )
            rows = cur.fetchall()
        except sqlite3.Error:
            rows = []
        for url, visit_count in rows:
            cat = classify_url_category(str(url))
            if cat not in totals:
                continue
            totals[cat] += max(int(visit_count or 0), 1) if count_visits else 1
        if count_visits:
            try:
                cur.execute(
                    """SELECT u.url, COUNT(v.rowid) FROM urls u
                       JOIN visits v ON v.url = u.id
                       WHERE u.url IS NOT NULL AND length(u.url) > 7
                       GROUP BY u.url
                       ORDER BY COUNT(v.rowid) DESC
                       LIMIT ?""",
                    (url_limit,),
                )
                for url, visits in cur.fetchall():
                    cat = classify_url_category(str(url))
                    if cat in visits_table:
                        visits_table[cat] += int(visits or 0)
            except sqlite3.Error:
                pass
            for key in totals:
                totals[key] = max(totals[key], visits_table[key])
        conn.close()
    except sqlite3.Error:
        return {k: 0 for k in _URL_CATEGORY_KEYS}
    finally:
        try:
            os.unlink(tmp_path)
        except OSError:
            pass
    return totals


def _count_firefox_all_categories(data: bytes, *, count_visits: bool) -> dict[str, int]:
    from app.services.url_category_counts import classify_url_category

    totals = {k: 0 for k in _URL_CATEGORY_KEYS}
    with tempfile.NamedTemporaryFile(suffix=".db", delete=False) as tmp:
        tmp.write(data)
        tmp_path = tmp.name
    try:
        conn = sqlite3.connect(f"file:{tmp_path}?mode=ro", uri=True)
        cur = conn.cursor()
        try:
            cur.execute(
                """SELECT p.url, p.visit_count FROM moz_places p
                   WHERE p.url IS NOT NULL AND length(p.url) > 7"""
            )
            rows = cur.fetchall()
        except sqlite3.Error:
            conn.close()
            return totals
        for url, visit_count in rows:
            cat = classify_url_category(str(url))
            if cat not in totals:
                continue
            totals[cat] += max(int(visit_count or 0), 1) if count_visits else 1
        conn.close()
    except sqlite3.Error:
        return {k: 0 for k in _URL_CATEGORY_KEYS}
    finally:
        try:
            os.unlink(tmp_path)
        except OSError:
            pass
    return totals


def _count_chrome_category(data: bytes, category: str, *, count_visits: bool) -> int:
    return int(_count_chrome_all_categories(data, count_visits=count_visits).get(category) or 0)


def _count_firefox_category(data: bytes, category: str, *, count_visits: bool) -> int:
    return int(_count_firefox_all_categories(data, count_visits=count_visits).get(category) or 0)


def count_browser_url_hits(
    db,
    job_id: str,
    patterns: list[re.Pattern],
    *,
    count_visits: bool = True,
) -> dict[str, Any]:
    rows = fetchall(db, _HISTORY_SQL, {"j": job_id})
    from app.config import get_settings

    max_db = max(int(getattr(get_settings(), "browser_inventory_max_db_bytes", 512_000_000) or 512_000_000), 1_000_000)
    contents = _read_job_files(db, job_id, rows, max_bytes=max_db)
    total = 0
    files_scanned = 0
    for row in rows:
        path = (row.get("file_path") or "").replace("\\", "/")
        data = contents.get(path)
        if not data or len(data) < 512:
            continue
        low = path.lower()
        if "firefox" in low or "mozilla" in low:
            n = _count_firefox_sqlite(data, patterns, count_visits=count_visits)
        else:
            n = _count_chrome_sqlite(data, patterns, count_visits=count_visits)
        if n > 0:
            files_scanned += 1
            total += n
    return {"count": total, "files_scanned": files_scanned}


def count_jump_list_destinations(db, job_id: str) -> dict[str, Any]:
    from app.parsers.jumplist import parse_jump_list
    from app.services.artifact_sections import _iter_jump_records

    total = 0
    embedded_lnk = 0
    custom_embedded = 0
    parsed_files = 0
    for _path, rec in _iter_jump_records(db, job_id):
        if rec.get("record_type") != "jump_list_file":
            continue
        kind = (rec.get("jump_list_kind") or "").lower()
        if kind == "custom":
            custom_embedded += int(rec.get("embedded_lnk_count") or 0)
            continue
        total += int(rec.get("entry_count") or 0)
        embedded_lnk += int(rec.get("embedded_lnk_count") or 0)

    if total <= 0:
        rows = fetchall(db, _JUMPLIST_SQL, {"j": job_id})
        custom_rows = fetchall(
            db,
            """SELECT file_path, size_bytes FROM job_artifacts
               WHERE job_id=:j AND file_path ILIKE '%.customDestinations-ms' AND size_bytes > 32""",
            {"j": job_id},
        )
        contents = _read_job_files(db, job_id, rows + custom_rows)
        for row in rows:
            path = row.get("file_path") or ""
            data = contents.get(path.replace("\\", "/"))
            if not data:
                continue
            for rec in parse_jump_list(data, path):
                if rec.get("record_type") != "jump_list_file":
                    continue
                total += int(rec.get("entry_count") or 0)
                embedded_lnk += int(rec.get("embedded_lnk_count") or 0)
                parsed_files += 1
        for row in custom_rows:
            path = row.get("file_path") or ""
            data = contents.get(path.replace("\\", "/"))
            if not data:
                continue
            for rec in parse_jump_list(data, path):
                if rec.get("record_type") != "jump_list_file":
                    continue
                custom_embedded += int(rec.get("embedded_lnk_count") or 0)

    return {
        "count": total,
        "embedded_lnk": embedded_lnk,
        "custom_embedded": custom_embedded,
        "parsed_files": parsed_files,
    }


def scan_registry_inventory(db, job_id: str) -> dict[str, Any]:
    from app.parsers.registry import parse_registry_hive

    feature_entries = 0
    feature_keys: set[str] = set()
    programs: dict[str, dict[str, Any]] = {}

    rows = fetchall(db, _HIVE_SQL, {"j": job_id})
    contents = _read_job_files(db, job_id, rows)

    seen_hive_hashes: set[str] = set()
    for row in rows:
        path = row.get("file_path") or ""
        norm_path = path.replace("\\", "/")
        digest = str(row.get("sha256") or "").strip().lower()
        # VSS/backup copies of the identical hive must not multiply registry records.
        if digest and digest in seen_hive_hashes:
            continue
        if digest:
            seen_hive_hashes.add(digest)
        data = contents.get(norm_path)
        if not data:
            continue
        for rec in parse_registry_hive(data, path):
            rt = rec.get("record_type")
            if rt == "feature_usage":
                key_path = str(rec.get("key_path") or rec.get("source") or "")
                metric = str(rec.get("metric") or "unknown")
                if metric == "app_launch_switched":
                    continue
                entry_n = int(rec.get("entry_count") or 0)
                metric_key = f"{norm_path}|{key_path}|{metric}"
                if metric_key not in feature_keys:
                    feature_keys.add(metric_key)
                    feature_entries += entry_n
            elif rt == "installed_program":
                name = (rec.get("display_name") or "").strip()
                if not name:
                    continue
                key = "|".join([
                    str(rec.get("source") or "").lower(),
                    str(rec.get("uninstall_key") or "").lower(),
                    name.lower(),
                ])
                if key not in programs:
                    programs[key] = rec

    ms = [p for p in programs.values() if p.get("is_microsoft")]
    non_ms = [p for p in programs.values() if not p.get("is_microsoft")]
    return {
        "feature_usage": feature_entries,
        "feature_keys": len(feature_keys),
        "microsoft_count": len(ms),
        "non_microsoft_count": len(non_ms),
        "samples_ms": [p.get("display_name") for p in ms[:12]],
        "samples_non_ms": [p.get("display_name") for p in non_ms[:20]],
    }
